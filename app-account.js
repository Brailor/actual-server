let express = require('express');
let bcrypt = require('bcrypt');
let uuid = require('uuid');
let fsp = require('node:fs/promises');
let errorMiddleware = require('./util/error-middleware');
let { validateUser } = require('./util/validate-user');
let { getAccountDb } = require('./account-db');
const config = require('./load-config');

let app = express();
app.use(errorMiddleware);

function init() {
  // eslint-disable-previous-line @typescript-eslint/no-empty-function
}

function hashPassword(password) {
  return bcrypt.hashSync(password, 12);
}

// Non-authenticated endpoints:
//
// /boostrap (special endpoint for setting up the instance, cant call again)
// /login

app.get('/needs-bootstrap', (req, res) => {
  let accountDb = getAccountDb();
  let rows = accountDb.all('SELECT * FROM auth');

  res.send({
    status: 'ok',
    data: { bootstrapped: rows.length > 0 }
  });
});

app.post('/bootstrap', (req, res) => {
  let { password } = req.body;
  let accountDb = getAccountDb();

  let rows = accountDb.all('SELECT * FROM auth');
  if (rows.length !== 0) {
    res.status(400).send({
      status: 'error',
      reason: 'already-bootstrapped'
    });
    return;
  }

  if (password == null || password === '') {
    res.status(400).send({ status: 'error', reason: 'invalid-password' });
    return;
  }

  // Hash the password. There's really not a strong need for this
  // since this is a self-hosted instance owned by the user.
  // However, just in case we do it.
  let hashed = hashPassword(password);
  accountDb.mutate('INSERT INTO auth (password) VALUES (?)', [hashed]);

  let token = uuid.v4();
  accountDb.mutate('INSERT INTO sessions (token) VALUES (?)', [token]);

  res.send({ status: 'ok', data: { token } });
});

app.post('/login', (req, res) => {
  let { password } = req.body;
  let accountDb = getAccountDb();

  let row = accountDb.first('SELECT * FROM auth');
  let confirmed = row && bcrypt.compareSync(password, row.password);

  let token = null;
  if (confirmed) {
    // Right now, tokens are permanent and there's just one in the
    // system. In the future this should probably evolve to be a
    // "session" that times out after a long time or something, and
    // maybe each device has a different token
    let row = accountDb.first('SELECT * FROM sessions');
    token = row.token;
  }

  res.send({ status: 'ok', data: { token } });
});

app.post('/change-password', (req, res) => {
  let user = validateUser(req, res);
  if (!user) return;

  let accountDb = getAccountDb();
  let { password } = req.body;

  if (password == null || password === '') {
    res.send({ status: 'error', reason: 'invalid-password' });
    return;
  }

  let hashed = hashPassword(password);

  // Note that this doesn't have a WHERE. This table only ever has 1
  // row (maybe that will change in the future? if this this will not work)
  accountDb.mutate('UPDATE auth SET password = ?', [hashed]);

  res.send({ status: 'ok', data: {} });
});

app.get('/validate', (req, res) => {
  let user = validateUser(req, res);
  if (user) {
    res.send({ status: 'ok', data: { validated: true } });
  }
});

app.get('/export', async (req, res) => {
  let user = validateUser(req, res);
  if (!user) return;

  // query the /user-files directory and grab the most recent .blob file
  let userFilesPath = config.userFiles;
  try {
    const dir = await fsp.opendir(userFilesPath);
    let files = [];
    for await (const dirent of dir) {
      if (dirent.isFile() && dirent.name.split('.').at(-1) === 'blob') {
        let stats = await fsp.stat(`${dir.path}/${dirent.name}`);
        files.push({ name: dirent.name, last_changed: stats.ctime });
      }
    }

    files.sort((fileA, fileB) => {
      let [timeA, timeB] = [
        fileA.last_changed.getTime(),
        fileB.last_changed.getTime()
      ];
      if (timeA > timeB) {
        return -1;
      } else if (timeB > timeA) {
        return 1;
      }

      return 0;
    });

    if (files.length < 1) {
      throw Error();
    }

    res.sendFile(`${userFilesPath}/${files.at(0).name}`);
  } catch (e) {
    res.send({ status: 'error', reason: 'could-not-locate-user-files' });
  }
});

app.use(errorMiddleware);

module.exports.handlers = app;
module.exports.init = init;
