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
const jwkToPem = require('jwk-to-pem')
const { getGlobalMetrics } = require('./metrics')

function Rotation (config) {
  this.realmUrl = config.realmUrl
  this.minTimeBetweenJwksRequests = config.minTimeBetweenJwksRequests
  this.httpTimeout = config.httpTimeout || 30000
  this.jwksCacheTtl = config.jwksCacheTtl || 86400
  this.maxRetries = config.maxRetries || 3
  this.retryBaseDelay = config.retryBaseDelay || 1000
  this.logger = config.logger || console
  this.metrics = config.metrics || getGlobalMetrics()
  this.jwks = []
  this.jwksCacheTime = 0
  this.lastTimeRequesTime = 0
}

Rotation.prototype.retrieveJWKs = function retrieveJWKs (callback) {
  const url = this.realmUrl + '/protocol/openid-connect/certs'
  const options = URL.parse(url); // eslint-disable-line
  options.method = 'GET'
  const self = this
  const startTime = Date.now()
  this.metrics.incrementCounter('jwksFetch', 'total')

  const promise = this._fetchWithRetry(options)
    .then(data => {
      self.metrics.incrementCounter('jwksFetch', 'success')
      self.metrics.recordDuration('jwksFetchDuration', Date.now() - startTime)
      self.metrics.setGauge('jwksCacheSize', data.keys ? data.keys.length : 0)
      return data
    })
    .catch(err => {
      self.metrics.incrementCounter('jwksFetch', 'failed')
      self.metrics.recordDuration('jwksFetchDuration', Date.now() - startTime)
      throw err
    })
  return nodeify(promise, callback)
}

Rotation.prototype._fetchWithRetry = function _fetchWithRetry (options, attempt = 0) {
  const self = this
  return new Promise((resolve, reject) => {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), self.httpTimeout)

    const req = getProtocol(options).request(options, (response) => {
      clearTimeout(timeoutId)
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.destroy()
        const err = new Error(`JWKS fetch failed with status ${response.statusCode}`)
        return self._handleRetry(err, options, attempt, resolve, reject)
      }
      let json = ''
      response.on('data', (d) => (json += d.toString()))
      response.on('end', () => {
        try {
          const data = JSON.parse(json)
          if (data.error) {
            self._handleRetry(new Error(data.error_description || data.error), options, attempt, resolve, reject)
          } else {
            resolve(data)
          }
        } catch (parseErr) {
          self._handleRetry(parseErr, options, attempt, resolve, reject)
        }
      })
    })

    controller.signal.addEventListener('abort', () => {
      req.destroy()
      const err = new Error(`JWKS request timeout after ${self.httpTimeout}ms`)
      self._handleRetry(err, options, attempt, resolve, reject)
    })

    req.on('error', (err) => {
      clearTimeout(timeoutId)
      self._handleRetry(err, options, attempt, resolve, reject)
    })
    req.end()
  })
}

Rotation.prototype._handleRetry = function _handleRetry (err, options, attempt, resolve, reject) {
  if (attempt < this.maxRetries - 1) {
    const delay = this.retryBaseDelay * Math.pow(2, attempt)
    this.logger.warn && this.logger.warn(`JWKS fetch attempt ${attempt + 1} failed: ${err.message}. Retrying in ${delay}ms`)
    setTimeout(() => {
      this._fetchWithRetry(options, attempt + 1)
        .then(resolve)
        .catch(reject)
    }, delay)
  } else {
    this.logger.error && this.logger.error(`JWKS fetch failed after ${this.maxRetries} attempts: ${err.message}`)
    reject(err)
  }
}

Rotation.prototype.getJWK = function getJWK (kid) {
  const currentTime = Date.now() / 1000
  const cacheExpired = currentTime > this.jwksCacheTime + this.jwksCacheTtl

  if (!cacheExpired && this.jwks.length > 0) {
    const key = this.jwks.find((key) => key.kid === kid)
    if (key) {
      this.metrics.incrementCounter('jwksFetch', 'cacheHits')
      return Promise.resolve(jwkToPem(key))
    }
  }

  const self = this
  const timeSinceLastRequest = currentTime - this.lastTimeRequesTime

  if (timeSinceLastRequest < this.minTimeBetweenJwksRequests) {
    const key = this.jwks.find((key) => key.kid === kid)
    if (key) {
      return Promise.resolve(jwkToPem(key))
    }
    this.logger.warn && this.logger.warn(`JWKS rate limit: ${this.minTimeBetweenJwksRequests - timeSinceLastRequest}s remaining. Kid ${kid} not in cache.`)
    return Promise.reject(new Error(`Key ${kid} not found and rate limited`))
  }

  return this.retrieveJWKs()
    .then(publicKeys => {
      self.lastTimeRequesTime = currentTime
      self.jwksCacheTime = currentTime
      self.jwks = publicKeys.keys
      const foundKey = self.jwks.find((key) => key.kid === kid)
      if (!foundKey) {
        throw new Error(`Key with kid ${kid} not found in JWKS`)
      }
      return jwkToPem(foundKey)
    })
}

Rotation.prototype.clearCache = function clearCache () {
  this.jwks.length = 0
}

const getProtocol = (opts) => {
  return opts.protocol === 'https:' ? https : http
}

const nodeify = (promise, cb) => {
  if (typeof cb !== 'function') return promise
  return promise.then((res) => cb(null, res)).catch((err) => cb(err))
}

module.exports = Rotation
