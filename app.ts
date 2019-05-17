import * as restify from 'restify';
let fetch = require('node-fetch').default;
//import { Bearer } from 'passport';

// this will not be checked in
import { appReg } from './appReg';

// Handle failed promises
process.on('unhandledRejection', (reason: Error | any, promise: Promise<any>) => {
	console.log('Caught Unhandled Rejection at:', reason.stack || reason)
})

export class AuthnServer {
	// TODO: reset cookie expiration to match token expiration
	// Server settings
	private refreshTime: string = new Date(new Date().getTime() + 86409000).toUTCString();
	private port: number = 8080;
	private dataStorage: authDataStore = new authDataStore();

	public hitEndpoint(req: restify.Request, res: restify.Response, next: restify.Next) {
		console.log(`Request for ${req.url}`);

		// Determine state via getting auth code
		let idToken: string = utils.getUrlParam(req.url, 'idToken');
		let endpoint: string = utils.getUrlParam(req.url, 'endpoint');

		// Use idToken to get a refreshToken and make the call
		if (idToken) {
			console.log(`using idToken to get refreshToken: ${idToken}`);
			let refreshToken: string = this.dataStorage.getRefreshToken(idToken);

			// Use refresh token to make the call
			if (refreshToken) {
				console.log(`got refreshToken: ${refreshToken}`);
				// Attempt to use cached token
				console.log(`using token to get token`);
				authHelper.getTokenByRefreshToken(refreshToken).then((responseFromAuth: authResult) => {
					// use the access token to hit the desired endpoint
					fetch(endpoint, {
						headers: {
							'Accept': 'application/json',
							'Authorization': 'Bearer ' + responseFromAuth.access_token
						}
					}).then((d: any) => {
						d.json().then((data: any) => {
							console.log(`First value: ${data}`);
							// Save the refreshtoken keyed on the idtoken
							this.dataStorage.saveRefreshToken(responseFromAuth.id_token, responseFromAuth.refresh_token)
							res.writeHead(200, {
								'Content-Type': 'text/html'
							});
							res.end(`First value: ${data}`); //.value[0].subject
						});
					}, (err: any) => {
						console.log(`Error hitting endpoint: ${err}`);
						res.writeHead(200, {
							'Content-Type': 'text/html',
							'Error': err
						});
						res.end(`Error hitting endpoint: ${err}`);
					});

					// Refresh token was invalid. Must restart auth process.
				}, (err: any) => {
					console.log(`refreshToken didn't work`);
					// TODO try using idToken to get new refresh token
					
					// redirect the user to interactive login for authorization code
					res.writeHead(301, {
						'Location': authHelper.getAuthzUrl(),
						'Error': err
					});
					console.log(`Invalid refresh token`);
					res.end();
				});
			}
			// We don't have a refreshToken for that idtoken
			else {
				// TODO try using idToken to get new refresh token
				
				// redirect the user to interactive login for authorization code
				res.writeHead(301, {
					'Location': authHelper.getAuthzUrl()
				});
				console.log(`No refresh token found for that id token in the data store`);
				res.end();
			}
		}
		else {
			// restart login flow
			res.writeHead(301, {
				'Location': authHelper.getAuthzUrl()
			});
			console.log(`No id token found in the call`);
			res.end();
		}

		next();
	}

	// Accept auth code, 1wayhash idToken, store hashed idToken with refreshToken, send hashed idToken
	public callback(req: restify.Request, res: restify.Response, next: restify.Next) {
		let code: string = utils.getUrlParam(req.url, 'code');
		console.log(`Request for ${req.url} with code=${code}`);

		if (code.length > 0) {
			console.log(`using auth code to get token`);
			authHelper.getTokenByAuthCode(code).then((responseFromAuth: authResult) => {

				if (responseFromAuth.refresh_token && responseFromAuth.id_token) {
					console.log(`saving refreshToken=${responseFromAuth.refresh_token} and idToken=${responseFromAuth.id_token}`);
					// TODO send the id token to the client -- HOW?
					// TODO make sure to hash the idtoken
					this.dataStorage.saveRefreshToken(responseFromAuth.id_token, responseFromAuth.refresh_token)
					res.writeHead(301, {
						'Location': `${appReg.endpoint}/hitEndpoint?` +
							`idToken=${responseFromAuth.id_token}&` +
							`endpoint=https://graph.microsoft.com/v1.0/me/messages` // TODO this shouldn't be hardcoded but where to store it?
					});
					res.end();

					/*
					fetch(`${appReg.endpoint}/hitEndpoint?` +
						`idToken=${responseFromAuth.id_token}&` +
						`endpoint=https://graph.microsoft.com/v1.0/me/messages`, {
						headers: {
							'Accept': 'application/json',
							'Authorization': 'Bearer ' + responseFromAuth.access_token
						}
					}).then((d: any) => {
						d.json().then((data: any) => {
							console.log(`First value: ${data}`);
							// Save the refreshtoken keyed on the idtoken
							authDataStore.saveRefreshToken(responseFromAuth.id_token, responseFromAuth.refresh_token)
							res.writeHead(200, {
								'Content-Type': 'text/html'
							});
							res.end(`First value: ${data}`); //.value[0].subject
						});
					}, (err: any) => {
						console.log(`Error hitting endpoint: ${err}`);
						res.writeHead(200, {
							'Content-Type': 'text/html',
							'Error': err
						});
						res.end(`Error hitting endpoint: ${err}`);
					});
					*/
				} else {
					console.log(`No refresh token, or no id token, in response`);
					// restart login flow
					res.writeHead(301, {
						'Location': authHelper.getAuthzUrl()
					});
					res.end();
				}
			});
		}
		else {
			console.log(`no code found in callback.`);

			// restart login flow
			res.writeHead(301, {
				'Location': authHelper.getAuthzUrl()
			});
			res.end();
		}
	}

	public makeAndRun() {
		let authnServer = restify.createServer({
			name: 'auth server middleware',
			version: '1.0.0'
		});
		authnServer.get('/hitEndpoint', this.hitEndpoint);
		authnServer.head('/hitEndpoint', this.hitEndpoint);
		authnServer.get('/callback', this.callback);
		authnServer.head('/callback', this.callback);
		authnServer.use(restify.plugins.jsonp());
		authnServer.use(restify.plugins.bodyParser({ mapParams: true }));

		// https solved through ngrok
		authnServer.listen(this.port, function () {
			console.log('%s listening at %s', authnServer.name, authnServer.url);
		});

		console.log(`Server running at ${this.port}`);
	}
}

export const authnServer: AuthnServer = new AuthnServer();
authnServer.makeAndRun();


export class utils {
	private tokenKV = [{ idToken: '' }];

	// Returns param value or empty string
	static getUrlParam(url: string | undefined, key: string): string {
		if (!url) {
			console.log(`bad url: ${url}`);
			return '';
		}

		let params: { [id: string]: string; } = {};
		url = url.substr(url.indexOf('?') + 1);
		var definitions: string[] = url.split('&');
		definitions.forEach((val, key) => {
			var parts: string[] = val.split('=', 2);
			params[parts[0]] = parts[1];
		});

		return (key && key in params) ? params[key] : '';
	}

	// Returns cookie or empty string
	static getCookie(request: restify.Request, key: string): string {
		let list: { [id: string]: string; } = {};
		let rc: string = request.headers.cookie ? request.headers.cookie.toString() : '';

		rc && rc.split(';').forEach(function (cookie: string) {
			let parts: string[] = cookie.split('=');
			let part: string | undefined = parts.shift();
			if (part)
				list[part.trim()] = decodeURI(parts.join('='));
		})

		return (key && key in list) ? list[key] : '';
	}
}

export class authHelper {
	// /token
	private static tokenEndpoint: string = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
	//private static tokenParametersCode: string = ``;
	//private static tokenParametersRefreshToken: string = ``;

	// /authorize
	private static authzendpoint: string = `https://login.microsoftonline.com/common/oauth2/v2.0/authorize`;
	private static authzparameters: string =
		`client_id=${appReg.appId}&` +
		`response_type=code&` +
		`redirect_uri=${appReg.redirectUri}&` +
		`scope=${appReg.scopes.join('%20')}`;

	// gets code authorization redirect
	static getAuthzUrl(): string {
		return `${authHelper.authzendpoint}?${authHelper.authzparameters}`;
	}

	// gets tokens from authorization code
	static async getTokenByAuthCode(code: string): Promise<authResult> {
		return new Promise(async (resolve, reject) => {
			var tokenParametersCode = `client_id=${appReg.appId}` +
				`&scope=${appReg.scopes.join('%20')}` +
				`&code=${code}` +
				`&redirect_uri=${appReg.redirectUri}` +
				`&grant_type=authorization_code` +
				`&client_secret=${appReg.appSecret}`;

			console.log(`Getting auth token from scope=${appReg.scopes.join('%20')}\nand grant type=authorization_code`);

			fetch(authHelper.tokenEndpoint, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded'
				},
				body: tokenParametersCode
			})
				.then((res: { json: () => { then: (arg0: (tokens: any) => void) => void; }; }) => {
					// get the json and resolve token details
					res.json().then((tokens) => {
						resolve(new authResult(tokens));
					});
				});
		});
	}

	// gets new access token using refresh token
	static getTokenByRefreshToken(refreshToken: string): Promise<authResult> {
		return new Promise(async (resolve, reject) => {
			var tokenParametersRefreshToken = `client_id=${appReg.appId}` +
				`&scope=${appReg.scopes.join('%20')}` +
				`&refresh_token=${refreshToken}` +
				`&redirect_uri=${appReg.redirectUri}` +
				`&grant_type=refresh_token` +
				`&client_secret=${appReg.appSecret}`;

			fetch(authHelper.tokenEndpoint, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded'
				},
				body: tokenParametersRefreshToken
			})
				.then((res: { json: () => { then: (arg0: (tokens: any) => void) => void; }; }) => {
					// get the json and resolve token details
					res.json().then((tokens: any) => {
						resolve(new authResult(tokens));
					});
				});
		});
	}
}

export class authResult {
	// This represents the parts we need from the responses at /token endpoint

	public access_token: string;
	public id_token: string;
	public refresh_token: string;

	public constructor(data: any) {
		this.access_token = data.access_token;
		this.id_token = data.id_token;
		this.refresh_token = data.refresh_token;
	}
}

export class authDataStore {
	// This simulates something like KeyVault

	private storage: Map<string, string> = new Map<string, string>();

	public constructor() {
		this.storage = new Map<string, string>();
	}

	public getRefreshToken(idToken: string): string {
		this.storage.forEach((key, val) => {
			if (this.storage.get(key) === idToken) {
				return val;
			}
		})
		return '';
	}

	public saveRefreshToken(idToken: string, refreshToken: string): boolean {
		let existed: boolean = this.storage.has(idToken);
		this.storage.set(idToken, refreshToken);
		return existed;
	}
}