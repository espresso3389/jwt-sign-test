/*jshint esversion: 11 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// キーを文字列化する
const keyToStr = (derKey, prefix) => prefix + derKey.toString('base64').replaceAll('=', '');

// 文字列からキー(DER形式)を復元する
const strToKey = (encodedKey, prefix) => {
    if (!encodedKey?.startsWith(prefix)) {
        throw new Error('Wrong key prefix.');
    }
    return Buffer.from(encodedKey.substring(prefix.length), 'base64');
};

// デバッグ時とかに判別できるようにするための分かりやすいプリフィックス
const publicKeyPrefix = 'pk_';
const secretKeyPrefix = 'sk_';

// 秘密鍵を復元
const decodeSecretKeyStr = (encodedSecretKey) => {
    return crypto.createPrivateKey(
        {key: strToKey(secretKeyStr, secretKeyPrefix), type: 'pkcs8', format: 'der' }
    ).export({ type: 'pkcs8', format: 'pem' });
};

// 公開鍵を復元
const decodePublicKeyStr = (encodedPublicKey) => {
    return crypto.createPublicKey(
        { key: strToKey(encodedPublicKey, publicKeyPrefix), type: 'spki', format: 'der' }
    ).export({ type: 'spki', format: 'pem' });
};

//
// サンプル
//

// 公開鍵ペアの生成 
const keyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  }
);

// 鍵ペアの文字列化
const publicKeyStr = keyToStr(keyPair.publicKey, publicKeyPrefix);
const secretKeyStr = keyToStr(keyPair.privateKey, secretKeyPrefix);
console.log(`Public Key: ${publicKeyStr}`);
console.log(`Secret Key: ${secretKeyStr}`);

// JWTの項目
// これらは署名側でJSONに付与され、検証側で同じ値であるかどうかを検証する
// https://openid-foundation-japan.github.io/draft-ietf-oauth-json-web-token-11.ja.html#issDef
const jwtClaims = {
    issuer: 'something_that_identifies_the_issuer_such_as_issuer_uri', // iss
    subject: 'something_that_describes_the_main_purpose_of_the_token', // sub
    audience: 'some_client_id_that_identify_the_recipient', // aud
};

// 署名
const resultJwt = jwt.sign(
    {
        data: {
            sample: 'これはサンプルです。署名を付けます。',
        },
    }, 
    decodeSecretKeyStr(secretKeyStr),
    Object.assign({
        algorithm: 'ES256',
        expiresIn: 3600, // 1時間で失効
    }, jwtClaims)
);
console.log(`JWT: ${resultJwt}`);

// https://jwt.io/ などで検証するための PEM でエンコードされた公開鍵
const publicKeyPem = decodePublicKeyStr(publicKeyStr);
console.log(`Public Key PEM: ${publicKeyPem}`);

// 署名検証側
const result = jwt.verify(
    resultJwt,
    publicKeyPem,
    Object.assign({
            algorithms: ['ES256'],
        },
        jwtClaims)
);
console.log(`Verified Result: ${JSON.stringify(result)}`);
