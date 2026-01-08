/*
 * Copyright 2016 Red Hat Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
'use strict'

function extractTokenFromRequest (request) {
  const authorization = request.headers.authorization || request.headers.Authorization
  if (!authorization) {
    return null
  }
  if (authorization.toLowerCase().startsWith('bearer')) {
    return authorization.split(' ').pop()
  }
  return authorization
}

function decodeToken (tokenString) {
  if (!tokenString) return null
  try {
    const parts = tokenString.split('.')
    if (parts.length !== 3) return null
    const payload = Buffer.from(parts[1], 'base64').toString('utf8')
    return JSON.parse(payload)
  } catch (e) {
    return null
  }
}

module.exports = function setup (realmResolver, clientResolver, keycloak) {
  return function setup (request, response, next) {
    const tokenString = extractTokenFromRequest(request)
    const tokenPayload = decodeToken(tokenString)

    let realmName = null
    let clientId = null

    if (tokenPayload) {
      if (tokenPayload.iss) {
        realmName = tokenPayload.iss.split('/').pop()
      }
      if (tokenPayload.azp) {
        clientId = tokenPayload.azp
      }
    }

    if (!realmName && realmResolver) {
      realmName = realmResolver(request)
    }

    if (!clientId && clientResolver) {
      clientId = clientResolver(request)
    }

    if (!clientId && realmName && keycloak && keycloak.defaultClientByRealm) {
      clientId = keycloak.defaultClientByRealm[realmName]
    }

    if (!realmName && !clientId) {
      throw new Error('Neither realm name nor client ID could be resolved')
    }

    request.kauth = {
      realmName,
      clientId
    }

    next()
  }
}
