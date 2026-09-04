'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getTodaysDate } = require('./index.js');

test('getTodaysDate returns the fixed ISO date', () => {
  assert.equal(getTodaysDate(), '2026-09-04');
});
