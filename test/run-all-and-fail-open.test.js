'use strict'

// Order-dependent result masking in composed auth. run:'all' must not change the
// logical AND/OR outcome: a later element must never mask an earlier one, in either
// direction (bypass = a pass masks a fail; false denial = a fail masks a pass).

const { test } = require('node:test')
const Fastify = require('fastify')
const fastifyAuth = require('..')

const OK = (req, reply, done) => done()
const FAIL = (req, reply, done) => done(new Error('deny'))

async function statusFor (composition, opts) {
  const app = Fastify()
  await app.register(fastifyAuth)
  app.after(() => {
    app.route({
      method: 'GET',
      url: '/',
      preHandler: app.auth(composition, opts),
      handler: (req, reply) => reply.send({ ok: true })
    })
  })
  const res = await app.inject({ method: 'GET', url: '/' })
  await app.close()
  return res.statusCode
}

test('run:all — F OR (F AND T) must be denied (earlier AND failure not masked)', async (t) => {
  const status = await statusFor([FAIL, [FAIL, OK]], { relation: 'or', run: 'all' })
  t.assert.strictEqual(status, 401)
})

test('run:all — (F AND T) OR (F AND T) must be denied', async (t) => {
  const status = await statusFor([[FAIL, OK], [FAIL, OK]], { relation: 'or', run: 'all' })
  t.assert.strictEqual(status, 401)
})

test('run:all — F OR (T AND T) still allowed (no false denial)', async (t) => {
  const status = await statusFor([FAIL, [OK, OK]], { relation: 'or', run: 'all' })
  t.assert.strictEqual(status, 200)
})

test('run:all — T OR (F AND F) still allowed (top-level OR short branch)', async (t) => {
  const status = await statusFor([OK, [FAIL, FAIL]], { relation: 'or', run: 'all' })
  t.assert.strictEqual(status, 200)
})

test('default run — F OR (F AND T) denied (unchanged behaviour)', async (t) => {
  const status = await statusFor([FAIL, [FAIL, OK]], { relation: 'or' })
  t.assert.strictEqual(status, 401)
})

// or + AND group: an earlier success must not be masked by a later failure.
test('run:all — (T AND T) OR (F AND T) must be allowed (earlier success not masked)', async (t) => {
  const status = await statusFor([[OK, OK], [FAIL, OK]], { relation: 'or', run: 'all' })
  t.assert.strictEqual(status, 200)
})

// A passing top-level function must not be masked by a later failing group.
test('run:all — T OR (F AND T) must be allowed (earlier success not masked)', async (t) => {
  const status = await statusFor([OK, [FAIL, OK]], { relation: 'or', run: 'all' })
  t.assert.strictEqual(status, 200)
})

// The failure latch must catch a failure at any position in the AND group.
test('run:all — F OR (T AND F AND T) must be denied (middle failure not masked)', async (t) => {
  const status = await statusFor([FAIL, [OK, FAIL, OK]], { relation: 'or', run: 'all' })
  t.assert.strictEqual(status, 401)
})

// and + OR group (mirror): an earlier failure must not be masked by a later pass.
test('run:all — F AND (T) must be denied (later OR group cannot mask earlier failure)', async (t) => {
  const status = await statusFor([FAIL, [OK]], { relation: 'and', run: 'all' })
  t.assert.strictEqual(status, 401)
})

test('run:all — (F) AND T must be denied (failing OR group not masked by later pass)', async (t) => {
  const status = await statusFor([[FAIL], OK], { relation: 'and', run: 'all' })
  t.assert.strictEqual(status, 401)
})

test('default run — (F) AND T must be denied (failing OR group is fail-closed)', async (t) => {
  const status = await statusFor([[FAIL], OK], { relation: 'and' })
  t.assert.strictEqual(status, 401)
})

test('run:all — (T) AND T still allowed (no false denial in and+OR)', async (t) => {
  const status = await statusFor([[OK], OK], { relation: 'and', run: 'all' })
  t.assert.strictEqual(status, 200)
})
