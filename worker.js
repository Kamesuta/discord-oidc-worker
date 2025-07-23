import * as config from './config.json'
import { Hono } from 'hono'
import * as jose from 'jose'

const algorithm = {
	name: 'RSASSA-PKCS1-v1_5',
	modulusLength: 2048,
	publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
	hash: { name: 'SHA-256' },
}

const importAlgo = {
	name: 'RSASSA-PKCS1-v1_5',
	hash: { name: 'SHA-256' },
}

async function loadOrGenerateKeyPair(KV) {
	let keyPair = {}
	let keyPairJson = await KV.get('keys', { type: 'json' })

	if (keyPairJson !== null) {
		keyPair.publicKey = await crypto.subtle.importKey('jwk', keyPairJson.publicKey, importAlgo, true, ['verify'])
		keyPair.privateKey = await crypto.subtle.importKey('jwk', keyPairJson.privateKey, importAlgo, true, ['sign'])

		return keyPair
	} else {
		keyPair = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])

		await KV.put('keys', JSON.stringify({
			privateKey: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
			publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey)
		}))

		return keyPair
	}

}

const app = new Hono()

app.get('/authorize/:scopemode', async (c) => {

	if (c.req.query('client_id') !== config.clientId
		|| c.req.query('redirect_uri') !== config.redirectURL
		|| !['guilds', 'email'].includes(c.req.param('scopemode'))) {
		return c.text('Bad request.', 400)
	}

	const params = new URLSearchParams({
		'client_id': config.clientId,
		'redirect_uri': config.redirectURL,
		'response_type': 'code',
		'scope': c.req.param('scopemode') == 'guilds' ? 'identify email guilds' : 'identify email',
		'state': c.req.query('state'),
		'prompt': 'none'
	}).toString()

	return c.redirect('https://discord.com/oauth2/authorize?' + params)
})

app.post('/token', async (c) => {
	try {
		console.log('POST /token - Starting request processing')
		
		const body = await c.req.parseBody()
		const code = body['code']
		console.log('Received code:', code ? 'present' : 'missing')
		
		const params = new URLSearchParams({
			'client_id': config.clientId,
			'client_secret': config.clientSecret,
			'redirect_uri': config.redirectURL,
			'code': code,
			'grant_type': 'authorization_code',
			'scope': 'identify email'
		}).toString()

		console.log('Requesting Discord token...')
		const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
			method: 'POST',
			body: params,
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			}
		})
		
		if (!tokenResponse.ok) {
			console.error('Discord token response error:', tokenResponse.status, tokenResponse.statusText)
			const errorText = await tokenResponse.text()
			console.error('Discord token error body:', errorText)
			return c.text('Discord authentication failed', 500)
		}
		
		const r = await tokenResponse.json()
		console.log('Discord token received successfully')

		if (!r || !r.access_token) {
			console.error('Invalid token response:', r)
			return new Response("Bad request.", { status: 400 })
		}
		
		console.log('Fetching user info...')
		const userInfoResponse = await fetch('https://discord.com/api/v10/users/@me', {
			headers: {
				'Authorization': 'Bearer ' + r['access_token']
			}
		})
		
		if (!userInfoResponse.ok) {
			console.error('User info response error:', userInfoResponse.status, userInfoResponse.statusText)
			return c.text('Failed to fetch user info', 500)
		}
		
		const userInfo = await userInfoResponse.json()
		console.log('User info received:', userInfo.id)

		if (!userInfo['verified']) {
			console.error('User email not verified')
			return c.text('Bad request.', 400)
		}

		let servers = []

		console.log('Fetching user guilds...')
		const serverResp = await fetch('https://discord.com/api/v10/users/@me/guilds', {
			headers: {
				'Authorization': 'Bearer ' + r['access_token']
			}
		})

		if (serverResp.status === 200) {
			const serverJson = await serverResp.json()
			servers = serverJson.map(item => {
				return item['id']
			})
			console.log('User is member of', servers.length, 'guilds')
		} else {
			console.log('Could not fetch guilds, status:', serverResp.status)
		}

		let roleClaims = {}

		if (c.env.DISCORD_TOKEN && 'serversToCheckRolesFor' in config) {
			console.log('Checking roles for configured guilds...')
			await Promise.all(config.serversToCheckRolesFor.map(async guildId => {
				if (servers.includes(guildId)) {
					try {
						console.log('Fetching roles for guild:', guildId)
						let memberPromise = fetch(`https://discord.com/api/v10/guilds/${guildId}/members/${userInfo['id']}`, {
							headers: {
								'Authorization': 'Bot ' + c.env.DISCORD_TOKEN
							}
						})
						// i had issues doing this any other way?
						const memberResp = await memberPromise
						
						if (!memberResp.ok) {
							console.error('Failed to fetch member info for guild', guildId, ':', memberResp.status)
							return
						}
						
						const memberJson = await memberResp.json()
						roleClaims[`roles:${guildId}`] = memberJson.roles
						console.log('Got', memberJson.roles.length, 'roles for guild', guildId)
					} catch (error) {
						console.error('Error fetching roles for guild', guildId, ':', error)
					}
				}
			}))
		}

		let preferred_username = userInfo['username']

		if (userInfo['discriminator'] && userInfo['discriminator'] !== '0'){
			preferred_username += `#${userInfo['discriminator']}`
		}

		let displayName = userInfo['global_name'] ?? userInfo['username']

		console.log('Generating JWT...')
		const keyPair = await loadOrGenerateKeyPair(c.env.KV)
		
		const idToken = await new jose.SignJWT({
			iss: 'https://cloudflare.com',
			aud: config.clientId,
			preferred_username,
			...userInfo,
			...roleClaims,
			email: userInfo['email'],
			global_name: userInfo['global_name'],
			name: displayName,
			guilds: servers
		})
			.setProtectedHeader({ alg: 'RS256' })
			.setExpirationTime('1h')
			.setAudience(config.clientId)
			.sign(keyPair.privateKey)

		console.log('JWT generated successfully')
		
		return c.json({
			...r,
			scope: 'identify email',
			id_token: idToken
		})
	} catch (error) {
		console.error('Error in /token endpoint:', error)
		console.error('Error stack:', error.stack)
		return c.text('Internal server error', 500)
	}
})

app.get('/jwks.json', async (c) => {
	let publicKey = (await loadOrGenerateKeyPair(c.env.KV)).publicKey
	return c.json({
		keys: [{
			alg: 'RS256',
			kid: 'jwtRS256',
			...(await crypto.subtle.exportKey('jwk', publicKey))
		}]
	})
})

export default app