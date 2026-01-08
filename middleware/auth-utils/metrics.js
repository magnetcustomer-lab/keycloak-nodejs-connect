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

function KeycloakMetrics () {
  this.counters = {
    tokenValidations: { total: 0, success: 0, failed: 0 },
    tokenRefresh: { total: 0, success: 0, failed: 0 },
    jwksFetch: { total: 0, success: 0, failed: 0, cacheHits: 0 },
    httpRequests: { total: 0, success: 0, failed: 0, retries: 0, timeouts: 0 }
  }

  this.histograms = {
    tokenValidationDuration: [],
    jwksFetchDuration: [],
    httpRequestDuration: []
  }

  this.gauges = {
    jwksCacheSize: 0,
    activeRequests: 0
  }
}

KeycloakMetrics.prototype.incrementCounter = function (category, name, value = 1) {
  if (this.counters[category] && typeof this.counters[category][name] === 'number') {
    this.counters[category][name] += value
  }
}

KeycloakMetrics.prototype.recordDuration = function (histogram, durationMs) {
  if (this.histograms[histogram]) {
    this.histograms[histogram].push(durationMs)
    if (this.histograms[histogram].length > 1000) {
      this.histograms[histogram] = this.histograms[histogram].slice(-1000)
    }
  }
}

KeycloakMetrics.prototype.setGauge = function (name, value) {
  if (typeof this.gauges[name] !== 'undefined') {
    this.gauges[name] = value
  }
}

KeycloakMetrics.prototype.getStats = function () {
  const calculatePercentile = (arr, p) => {
    if (arr.length === 0) return 0
    const sorted = [...arr].sort((a, b) => a - b)
    const idx = Math.ceil(p / 100 * sorted.length) - 1
    return sorted[Math.max(0, idx)]
  }

  const calculateAvg = (arr) => {
    if (arr.length === 0) return 0
    return arr.reduce((a, b) => a + b, 0) / arr.length
  }

  return {
    counters: this.counters,
    gauges: this.gauges,
    histograms: {
      tokenValidationDuration: {
        count: this.histograms.tokenValidationDuration.length,
        avg: calculateAvg(this.histograms.tokenValidationDuration),
        p50: calculatePercentile(this.histograms.tokenValidationDuration, 50),
        p95: calculatePercentile(this.histograms.tokenValidationDuration, 95),
        p99: calculatePercentile(this.histograms.tokenValidationDuration, 99)
      },
      jwksFetchDuration: {
        count: this.histograms.jwksFetchDuration.length,
        avg: calculateAvg(this.histograms.jwksFetchDuration),
        p50: calculatePercentile(this.histograms.jwksFetchDuration, 50),
        p95: calculatePercentile(this.histograms.jwksFetchDuration, 95),
        p99: calculatePercentile(this.histograms.jwksFetchDuration, 99)
      },
      httpRequestDuration: {
        count: this.histograms.httpRequestDuration.length,
        avg: calculateAvg(this.histograms.httpRequestDuration),
        p50: calculatePercentile(this.histograms.httpRequestDuration, 50),
        p95: calculatePercentile(this.histograms.httpRequestDuration, 95),
        p99: calculatePercentile(this.histograms.httpRequestDuration, 99)
      }
    }
  }
}

KeycloakMetrics.prototype.reset = function () {
  Object.keys(this.counters).forEach(cat => {
    Object.keys(this.counters[cat]).forEach(key => {
      this.counters[cat][key] = 0
    })
  })
  Object.keys(this.histograms).forEach(key => {
    this.histograms[key] = []
  })
}

let globalMetrics = null

module.exports = {
  KeycloakMetrics,
  getGlobalMetrics: function () {
    if (!globalMetrics) {
      globalMetrics = new KeycloakMetrics()
    }
    return globalMetrics
  },
  resetGlobalMetrics: function () {
    globalMetrics = null
  }
}
