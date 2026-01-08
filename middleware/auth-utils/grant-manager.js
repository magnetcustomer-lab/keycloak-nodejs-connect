/*!
 * Copyright 2014 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict'

const URL = require('url')
const http = require('http')
const https = require('https')
const crypto = require('crypto')
const querystring = require('querystring')
const Grant = require('./grant')
const Token = require('./token')
const Rotation = require('./rotation')
const { getGlobalMetrics } = require('./metrics')

/**
 * Construct a grant manager.
 *
 * @param {Config} config Config object.
 *
 * @constructor
 */
function GrantManager (config) {
  this.realmUrl = config.realmUrl
  this.clientId = config.clientId
  this.secret = config.secret
  this.publicKey = config.publicKey
  this.public = config.public
  this.bearerOnly = config.bearerOnly
  this.notBefore = 0
  this.rotation = new Rotation(config)
  this.verifyTokenAudience = config.verifyTokenAudience
  this.httpTimeout = config.httpTimeout || 30000
  this.maxRetries = config.maxRetries || 3
  this.retryBaseDelay = config.retryBaseDelay || 1000
  this.trustedAzp = config.trustedAzp || []
  this.logger = config.logger || console
  this.metrics = config.metrics || getGlobalMetrics()
}

/**
 * Use the direct grant API to obtain a grant from Keycloak.
 *
 * The direct grant API must be enabled for the configured realm
 * for this method to work. This function ostensibly provides a
 * non-interactive, programatic way to login to a Keycloak realm.
 *
 * This method can either accept a callback as the last parameter
 * or return a promise.
 *
 * @param {String} username The username.
 * @param {String} password The cleartext password.
 * @param {Function} callback Optional callback, if not using promises.
 */
GrantManager.prototype.obtainDirectly = function obtainDirectly (username, password,
  callback, scopeParam) {
  const params = {
    client_id: this.clientId,
    username,
    password,
    grant_type: 'password',
    scope: scopeParam || 'openid'
  }
  const handler = createHandler(this)
  const options = postOptions(this)
  return nodeify(fetch(this, handler, options, params), callback)
}

/**
 * Obtain a grant from a previous interactive login which results in a code.
 *
 * This is typically used by servers which receive the code through a
 * redirect_uri when sending a user to Keycloak for an interactive login.
 *
 * An optional session ID and host may be provided if there is desire for
 * Keycloak to be aware of this information.  They may be used by Keycloak
 * when session invalidation is triggered from the Keycloak console itself
 * during its postbacks to `/k_logout` on the server.
 *
 * This method returns or promise or may optionally take a callback function.
 *
 * @param {String} code The code from a successful login redirected from Keycloak.
 * @param {String} sessionId Optional opaque session-id.
 * @param {String} sessionHost Optional session host for targetted Keycloak console post-backs.
 * @param {Function} callback Optional callback, if not using promises.
 */
GrantManager.prototype.obtainFromCode = function obtainFromCode (request, code, sessionId, sessionHost, callback) {
  const params = {
    client_session_state: sessionId,
    client_session_host: sessionHost,
    code,
    grant_type: 'authorization_code',
    client_id: this.clientId,
    redirect_uri: request.session ? request.session.auth_redirect_uri : {}
  }
  const handler = createHandler(this)
  const options = postOptions(this)

  return nodeify(fetch(this, handler, options, params), callback)
}

GrantManager.prototype.checkPermissions = function obtainPermissions (authzRequest, request, callback) {
  const params = {
    grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket'
  }

  if (authzRequest.audience) {
    params.audience = authzRequest.audience
  } else {
    params.audience = this.clientId
  }

  if (authzRequest.response_mode) {
    params.response_mode = authzRequest.response_mode
  }

  if (authzRequest.claim_token) {
    params.claim_token = authzRequest.claim_token
    params.claim_token_format = authzRequest.claim_token_format
  }

  const options = postOptions(this)

  if (this.public) {
    if (request.kauth && request.kauth.grant && request.kauth.grant.access_token) {
      options.headers.Authorization = 'Bearer ' + request.kauth.grant.access_token.token
    }
  } else {
    const header = request.headers.authorization
    let bearerToken

    if (header && (header.indexOf('bearer ') === 0 || header.indexOf('Bearer ') === 0)) {
      bearerToken = header.substring(7)
    }

    if (!bearerToken) {
      if (request.kauth && request.kauth.grant && request.kauth.grant.access_token) {
        bearerToken = request.kauth.grant.access_token.token
      } else {
        return Promise.reject(new Error('No bearer in header'))
      }
    }

    params.subject_token = bearerToken
  }

  let permissions = authzRequest.permissions

  if (!permissions) {
    permissions = []
  }

  for (let i = 0; i < permissions.length; i++) {
    const resource = permissions[i]
    let permission = resource.id

    if (resource.scopes && resource.scopes.length > 0) {
      permission += '#'

      for (let j = 0; j < resource.scopes.length; j++) {
        const scope = resource.scopes[j]
        if (permission.indexOf('#') !== permission.length - 1) {
          permission += ','
        }
        permission += scope
      }
    }

    if (!params.permission) {
      params.permission = []
    }

    params.permission.push(permission)
  }

  const manager = this

  const handler = (resolve, reject, json) => {
    try {
      if (authzRequest.response_mode === 'decision' || authzRequest.response_mode === 'permissions') {
        callback(JSON.parse(json))
      } else {
        resolve(manager.createGrant(json))
      }
    } catch (err) {
      reject(err)
    }
  }

  return nodeify(fetch(this, handler, options, params))
}

/**
 * Obtain a service account grant.
 * Client option 'Service Accounts Enabled' needs to be on.
 *
 * This method returns or promise or may optionally take a callback function.
 *
 * @param {Function} callback Optional callback, if not using promises.
 */
GrantManager.prototype.obtainFromClientCredentials = function obtainFromlientCredentials (callback, scopeParam) {
  const params = {
    grant_type: 'client_credentials',
    scope: scopeParam || 'openid',
    client_id: this.clientId
  }
  const handler = createHandler(this)
  const options = postOptions(this)

  return nodeify(fetch(this, handler, options, params), callback)
}

GrantManager.prototype.exchangeToken = function exchangeToken (options, callback) {
  const subjectToken = typeof options.subjectToken === 'object'
    ? options.subjectToken.token
    : options.subjectToken

  const params = {
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: subjectToken,
    subject_token_type: options.subjectTokenType || 'urn:ietf:params:oauth:token-type:access_token',
    client_id: this.clientId
  }

  if (options.audience) {
    params.audience = options.audience
  }

  if (options.requestedTokenType) {
    params.requested_token_type = options.requestedTokenType
  }

  if (options.scope) {
    params.scope = options.scope
  }

  if (options.actorToken) {
    const actorToken = typeof options.actorToken === 'object'
      ? options.actorToken.token
      : options.actorToken
    params.actor_token = actorToken
    params.actor_token_type = options.actorTokenType || 'urn:ietf:params:oauth:token-type:access_token'
  }

  const handler = createHandler(this)
  const requestOptions = postOptions(this)

  this.metrics.incrementCounter('tokenRefresh', 'total')
  const self = this

  const promise = fetch(this, handler, requestOptions, params)
    .then(grant => {
      self.metrics.incrementCounter('tokenRefresh', 'success')
      return grant
    })
    .catch(err => {
      self.metrics.incrementCounter('tokenRefresh', 'failed')
      throw err
    })

  return nodeify(promise, callback)
}

/**
 * Ensure that a grant is *fresh*, refreshing if required & possible.
 *
 * If the access_token is not expired, the grant is left untouched.
 *
 * If the access_token is expired, and a refresh_token is available,
 * the grant is refreshed, in place (no new object is created),
 * and returned.
 *
 * If the access_token is expired and no refresh_token is available,
 * an error is provided.
 *
 * The method may either return a promise or take an optional callback.
 *
 * @param {Grant} grant The grant object to ensure freshness of.
 * @param {Function} callback Optional callback if promises are not used.
 */
GrantManager.prototype.ensureFreshness = function ensureFreshness (grant, callback) {
  if (!grant.isExpired()) {
    return nodeify(Promise.resolve(grant), callback)
  }

  if (!grant.refresh_token) {
    return nodeify(Promise.reject(new Error('Unable to refresh without a refresh token')), callback)
  }

  if (grant.refresh_token.isExpired()) {
    return nodeify(Promise.reject(new Error('Unable to refresh with expired refresh token')), callback)
  }

  const params = {
    grant_type: 'refresh_token',
    refresh_token: grant.refresh_token.token,
    client_id: this.clientId
  }
  const handler = refreshHandler(this, grant)
  const options = postOptions(this)

  return nodeify(fetch(this, handler, options, params), callback)
}

/**
 * Perform live validation of an `access_token` against the Keycloak server.
 *
 * @param {Token|String} token The token to validate.
 * @param {Function} callback Callback function if not using promises.
 *
 * @return {boolean} `false` if the token is invalid, or the same token if valid.
 */
GrantManager.prototype.validateAccessToken = function validateAccessToken (token, callback) {
  let t = token
  if (typeof token === 'object') {
    t = token.token
  }
  const params = {
    token: t,
    client_secret: this.secret,
    client_id: this.clientId
  }
  const options = postOptions(this, '/protocol/openid-connect/token/introspect')
  const handler = validationHandler(this, token)

  return nodeify(fetch(this, handler, options, params), callback)
}

GrantManager.prototype.userInfo = function userInfo (token, callback) {
  const url = this.realmUrl + '/protocol/openid-connect/userinfo'
  const options = URL.parse(url); // eslint-disable-line
  options.method = 'GET'

  let t = token
  if (typeof token === 'object') t = token.token

  options.headers = {
    Authorization: 'Bearer ' + t,
    Accept: 'application/json',
    'X-Client': 'keycloak-nodejs-connect'
  }

  const promise = new Promise((resolve, reject) => {
    const req = getProtocol(options).request(options, (response) => {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.destroy()
        return reject(new Error('Error fetching account'))
      }
      let json = ''
      response.on('data', (d) => (json += d.toString()))
      response.on('end', () => {
        const data = JSON.parse(json)
        if (data.error) reject(data)
        else resolve(data)
      })
    })
    req.on('error', reject)
    req.end()
  })

  return nodeify(promise, callback)
}

GrantManager.prototype.getAccount = function getAccount () {
  console.error('GrantManager#getAccount is deprecated. See GrantManager#userInfo')
  return this.userInfo.apply(this, arguments)
}

GrantManager.prototype.isGrantRefreshable = function isGrantRefreshable (grant) {
  return !this.bearerOnly && (grant && grant.refresh_token)
}

/**
 * Create a `Grant` object from a string of JSON data.
 *
 * This method creates the `Grant` object, including
 * the `access_token`, `refresh_token` and `id_token`
 * if available, and validates each for expiration and
 * against the known public-key of the server.
 *
 * @param {String} rawData The raw JSON string received from the Keycloak server or from a client.
 * @return {Promise} A promise reoslving a grant.
 */
GrantManager.prototype.createGrant = function createGrant (rawData) {
  let grantData = rawData
  if (typeof rawData !== 'object') grantData = JSON.parse(grantData)

  const grant = new Grant({
    access_token: (grantData.access_token ? new Token(grantData.access_token, this.clientId) : undefined),
    refresh_token: (grantData.refresh_token ? new Token(grantData.refresh_token) : undefined),
    id_token: (grantData.id_token ? new Token(grantData.id_token) : undefined),
    expires_in: grantData.expires_in,
    token_type: grantData.token_type,
    __raw: rawData
  })

  if (this.isGrantRefreshable(grant)) {
    return new Promise((resolve, reject) => {
      this.ensureFreshness(grant)
        .then(g => this.validateGrant(g))
        .then(g => resolve(g))
        .catch(err => reject(err))
    })
  } else {
    return this.validateGrant(grant)
  }
}

/**
 * Validate the grant and all tokens contained therein.
 *
 * This method examines a grant (in place) and rejects
 * if any of the tokens are invalid. After this method
 * resolves, the passed grant is guaranteed to have
 * valid tokens.
 *
 * @param {Grant} The grant to validate.
 *
 * @return {Promise} That resolves to a validated grant or
 * rejects with an error if any of the tokens are invalid.
 */
GrantManager.prototype.validateGrant = function validateGrant (grant) {
  const self = this
  const validateGrantToken = (grant, tokenName, expectedType) => {
    return new Promise((resolve, reject) => {
    // check the access token
      this.validateToken(grant[tokenName], expectedType).then(token => {
        grant[tokenName] = token
        resolve()
      }).catch((err) => {
        reject(new Error('Grant validation failed. Reason: ' + err.message))
      })
    })
  }
  return new Promise((resolve, reject) => {
    const promises = []
    promises.push(validateGrantToken(grant, 'access_token', 'Bearer'))
    if (!self.bearerOnly) {
      if (grant.id_token) {
        promises.push(validateGrantToken(grant, 'id_token', 'ID'))
      }
    }
    Promise.all(promises).then(() => {
      resolve(grant)
    }).catch((err) => {
      reject(new Error(err.message))
    })
  })
}

/**
 * Validate a token.
 *
 * This method accepts a token, and returns a promise
 *
 * If the token is valid the promise will be resolved with the token
 *
 * If the token is undefined or fails validation an applicable error is returned
 *
 * @return {Promise} That resolve a token
 */
GrantManager.prototype.validateToken = function validateToken (token, expectedType) {
  const startTime = Date.now()
  const self = this
  this.metrics.incrementCounter('tokenValidations', 'total')

  return new Promise((resolve, reject) => {
    const recordAndReject = (err) => {
      self.metrics.incrementCounter('tokenValidations', 'failed')
      self.metrics.recordDuration('tokenValidationDuration', Date.now() - startTime)
      reject(err)
    }
    const recordAndResolve = (result) => {
      self.metrics.incrementCounter('tokenValidations', 'success')
      self.metrics.recordDuration('tokenValidationDuration', Date.now() - startTime)
      resolve(result)
    }

    if (!token) {
      recordAndReject(new Error('invalid token (missing)'))
    } else if (token.isExpired()) {
      recordAndReject(new Error('invalid token (expired)'))
    } else if (!token.signed) {
      recordAndReject(new Error('invalid token (not signed)'))
    } else if (token.content.typ !== expectedType) {
      recordAndReject(new Error('invalid token (wrong type)'))
    } else if (token.content.iat < this.notBefore) {
      recordAndReject(new Error('invalid token (stale token)'))
    } else if (token.content.iss !== this.realmUrl) {
      recordAndReject(new Error('invalid token (wrong ISS)'))
    } else {
      const audienceData = Array.isArray(token.content.aud) ? token.content.aud : [token.content.aud]
      if (expectedType === 'ID') {
        if (!audienceData.includes(this.clientId)) {
          recordAndReject(new Error('invalid token (wrong audience)'))
          return
        }
        if (token.content.azp && token.content.azp !== this.clientId) {
          const azpAllowed = this.trustedAzp.includes(token.content.azp)
          if (!azpAllowed) {
            recordAndReject(new Error('invalid token (authorized party should match client id or be in trusted list)'))
            return
          }
        }
      } else if (this.verifyTokenAudience) {
        if (!audienceData.includes(this.clientId)) {
          recordAndReject(new Error('invalid token (wrong audience)'))
          return
        }
      }
      const verify = crypto.createVerify('RSA-SHA256')
      if (this.publicKey) {
        try {
          verify.update(token.signed)
          if (!verify.verify(this.publicKey, token.signature, 'base64')) {
            recordAndReject(new Error('invalid token (signature)'))
          } else {
            recordAndResolve(token)
          }
        } catch (err) {
          recordAndReject(new Error('Misconfigured parameters while validating token. Check your keycloak.json file!'))
        }
      } else {
        this.rotation.getJWK(token.header.kid).then(key => {
          verify.update(token.signed)
          if (!verify.verify(key, token.signature)) {
            recordAndReject(new Error('invalid token (public key signature)'))
          } else {
            recordAndResolve(token)
          }
        }).catch((err) => {
          recordAndReject(new Error('failed to load public key to verify token. Reason: ' + err.message))
        })
      }
    }
  })
}

const getProtocol = (opts) => {
  return opts.protocol === 'https:' ? https : http
}

const nodeify = (promise, cb) => {
  if (typeof cb !== 'function') return promise
  return promise.then((res) => cb(null, res)).catch((err) => cb(err))
}

const createHandler = (manager) => (resolve, reject, json) => {
  try {
    resolve(manager.createGrant(json))
  } catch (err) {
    reject(err)
  }
}

const refreshHandler = (manager, grant) => (resolve, reject, json) => {
  manager.createGrant(json)
    .then((grant) => resolve(grant))
    .catch((err) => reject(err))
}

const validationHandler = (manager, token) => (resolve, reject, json) => {
  const data = JSON.parse(json)
  if (!data.active) resolve(false)
  else resolve(token)
}

const postOptions = (manager, path) => {
  const realPath = path || '/protocol/openid-connect/token'
  const opts = URL.parse(manager.realmUrl + realPath); // eslint-disable-line
  opts.headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Client': 'keycloak-nodejs-connect'
  }
  if (!manager.public) {
    opts.headers.Authorization = 'Basic ' + Buffer.from(manager.clientId + ':' + manager.secret).toString('base64')
  }
  opts.method = 'POST'
  return opts
}

const fetch = (manager, handler, options, params, attempt = 0) => {
  const startTime = Date.now()
  if (attempt === 0) {
    manager.metrics.incrementCounter('httpRequests', 'total')
  } else {
    manager.metrics.incrementCounter('httpRequests', 'retries')
  }

  return new Promise((resolve, reject) => {
    const data = (typeof params === 'string' ? params : querystring.stringify(params))
    options.headers['Content-Length'] = data.length

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), manager.httpTimeout)

    const req = getProtocol(options).request(options, (response) => {
      clearTimeout(timeoutId)
      if (response.statusCode < 200 || response.statusCode > 299) {
        response.destroy()
        const err = new Error(response.statusCode + ':' + http.STATUS_CODES[response.statusCode])
        return handleFetchRetry(manager, err, handler, options, params, attempt, resolve, reject, startTime)
      }
      let json = ''
      response.on('data', (d) => (json += d.toString()))
      response.on('end', () => {
        manager.metrics.incrementCounter('httpRequests', 'success')
        manager.metrics.recordDuration('httpRequestDuration', Date.now() - startTime)
        handler(resolve, reject, json)
      })
    })

    controller.signal.addEventListener('abort', () => {
      req.destroy()
      manager.metrics.incrementCounter('httpRequests', 'timeouts')
      const err = new Error(`Request timeout after ${manager.httpTimeout}ms`)
      handleFetchRetry(manager, err, handler, options, params, attempt, resolve, reject, startTime)
    })

    req.write(data)
    req.on('error', (err) => {
      clearTimeout(timeoutId)
      handleFetchRetry(manager, err, handler, options, params, attempt, resolve, reject, startTime)
    })
    req.end()
  })
}

const handleFetchRetry = (manager, err, handler, options, params, attempt, resolve, reject, startTime) => {
  const isRetryable = isRetryableError(err)
  if (isRetryable && attempt < manager.maxRetries - 1) {
    const delay = manager.retryBaseDelay * Math.pow(2, attempt)
    manager.logger.warn && manager.logger.warn(`Request attempt ${attempt + 1} failed: ${err.message}. Retrying in ${delay}ms`)
    setTimeout(() => {
      fetch(manager, handler, options, params, attempt + 1)
        .then(resolve)
        .catch(reject)
    }, delay)
  } else {
    manager.metrics.incrementCounter('httpRequests', 'failed')
    manager.metrics.recordDuration('httpRequestDuration', Date.now() - startTime)
    if (attempt > 0) {
      manager.logger.error && manager.logger.error(`Request failed after ${attempt + 1} attempts: ${err.message}`)
    }
    reject(err)
  }
}

const isRetryableError = (err) => {
  if (err.message.includes('timeout')) return true
  if (err.message.includes('ECONNRESET')) return true
  if (err.message.includes('ETIMEDOUT')) return true
  if (err.message.includes('ECONNREFUSED')) return true
  const statusMatch = err.message.match(/^(\d+):/)
  if (statusMatch) {
    const status = parseInt(statusMatch[1], 10)
    return status >= 500 || status === 429
  }
  return false
}

module.exports = GrantManager
