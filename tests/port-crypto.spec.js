'use strict';

const {describe, it} = require('mocha');
const {assert} = require('chai');
const myBuffer = require('buffer/').Buffer;

const origCrypto = require('./orig-my-crypto');
const portedCrypto = require('../src/port-crypto');
const {prepareForStringifyObject} = require('../src/utils');

describe('Ported with crypto-js', () => {
    before(async function() {
        this.timeout(15000);
    });

    after(async function() {
        this.timeout(15000);
    });

    it('should be fine for "ripemd160" for text', async () => {
        const text = 'The quick brown fox jumps over the lazy dog';

        assert.equal(origCrypto.ripemd160(text), portedCrypto.ripemd160(text));
    });

    it('should be fine for "scrypt" for text (hex salt)', async function() {
        this.timeout(10000);
        // const password = 'The quick brown fox jumps over the lazy dog';
        const password = 'blah-blah';
        const salt = portedCrypto.randomBytes(16);

        const origHash = origCrypto.scrypt(password, Buffer.from(salt, 'hex')).toString('hex');
        const portedHash = portedCrypto.scrypt(password, salt);

        console.log(origHash);
        console.log(portedHash);

        assert.equal(
            origHash.toString('hex'),
            portedHash
        );
    });

    it('should create key (salt is a String)', async function() {
        this.timeout(10000);

        const salt = '988266b1b7724f596f4625520b5cbfde';
        const password = 'blah-blah';

        const {key: bufOrigKey} = origCrypto.createKey('scrypt', password, Buffer.from(salt, 'hex'));
        const {key: strPortedKey} = portedCrypto.createKey('scrypt', password, salt);
        assert.equal(bufOrigKey.toString('hex'), strPortedKey);

        console.log(bufOrigKey.toString('hex'));
        console.log(strPortedKey);
    });

    it('should create key (salt is a Buffer)', async function() {
        this.timeout(10000);

        const salt = '988266b1b7724f596f4625520b5cbfde';
        const buffSalt=new myBuffer(salt);
        const password = 'blah-blah';

        const {key: bufOrigKey} = origCrypto.createKey('scrypt', password, salt);
        const {key: strPortedKey} = portedCrypto.createKey('scrypt', password, buffSalt);
        assert.equal(strPortedKey.length, 64);
        assert.equal(bufOrigKey.toString('hex'), strPortedKey);
    });

    it('should generate "randomBytes"', async () => {
        const result = portedCrypto.randomBytes(32);

        assert.equal(result.length, 64);
    });

    it('should _encrypt (predefined key & iv)', async function() {
        this.timeout(10000);

        const pk = 'a'.repeat(64);
        const key = '074f9f82513f1ef8fd2e4eb34382bb162857d70e6c0a2fd7d467b2189f267efd';
        const iv = '62fce31fc117a4486af8b3b038bc8a77';

        const strPortedEnc = await portedCrypto._encrypt(pk, key, iv);
        const buffOrigEnc = await origCrypto._encrypt(
            Buffer.from(pk, 'hex'),
            Buffer.from(key, 'hex'),
            Buffer.from(iv, 'hex')
        );

        assert.equal(strPortedEnc, buffOrigEnc.toString('hex'));
        console.log(strPortedEnc);
    });

    it('should encrypt PK', async function() {
        this.timeout(10000);

        const pk = 'a'.repeat(64);
        const pass = '12345';

        const result = await portedCrypto.encrypt(pass, pk);
        console.log(JSON.stringify(result));
    });

    it('should decrypt keystore (external static)', async function() {
        this.timeout(10000);

        const store = {
            "address": "Uxd17084938bbc7485ef5d912e14986e1d1b05ad55",
            "iv": "4ba31b1aa3e1f75e7b030f6275b1d4bf",
            "encrypted": "cc58076d561eebeccb1f5039c396d73afbad1dc23b7f4b5bafd1e37ec8f8b237",
            "salt": "9a07bb8ec808dc7eec43872fa6905087",
            "hashOptions": {"N": 262144, "p": 1, "r": 8, "maxmem": 270532608},
            "keyAlgo": "scrypt",
            "version": 1.1
        };
        const pass = '12345';

        const result = portedCrypto.decrypt(pass, store);

        assert.equal(result, 'b'.repeat(64));
    });

    it('should decrypt keystore (external dynamic)', async function() {
        this.timeout(25000);

        const pk = 'd'.repeat(64);
        const pass = '12345';

        const objResult = prepareForStringifyObject(await origCrypto.encrypt(pass, Buffer.from(pk, 'hex')));

        const result = origCrypto.decrypt(pass, objResult).toString('hex');
        const resultPorted = portedCrypto.decrypt(pass, objResult).toString('hex');

        console.log(result);
        console.log(resultPorted);

        assert.equal(result, 'd'.repeat(64));
        assert.equal(resultPorted, 'd'.repeat(64));

    });

    it('should decrypt keystore (local dynamic)', async function() {
        this.timeout(25000);

        const pk = 'd'.repeat(64);
        const pass = 'blah-blah';

        const objResult = await portedCrypto.encrypt(pass, pk);

        const result = origCrypto.decrypt(pass, objResult).toString('hex');
        const resultPorted = portedCrypto.decrypt(pass, objResult).toString('hex');

        console.log(result);
        console.log(resultPorted);

        assert.equal(result, 'd'.repeat(64));
        assert.equal(resultPorted, 'd'.repeat(64));

    });

    describe('elliptic', async () =>{
        it('should create keypair', async () => {
            const kp = portedCrypto.createKeyPair();
        });

        it('should create keypair from private', async () => {
            const pk='c'.repeat(64);
            const kp=portedCrypto.keyPairFromPrivate(pk);

            assert.equal(kp.getAddress(false), 'aa37ca8400ee3eae9af8c850c064cb05a3d50788');
        });

        it('should sign hash', async () => {
            const strHash='f'.repeat(64);
            const pk='c'.repeat(64);

            const signature=portedCrypto.sign(strHash, pk);
            const signatureOrig=origCrypto.sign(strHash, pk);

            assert.equal(signature.length, 65);
            assert.equal(signature.toString('hex'), signatureOrig.toString('hex'));
            console.log(signatureOrig.toString('hex'));
        });

        it('should recovery addr from signature', async () => {
            const strHash='f'.repeat(64);
            const pk='c'.repeat(64);
            const signature=portedCrypto.sign(strHash, pk);

            const kp = portedCrypto.keyPairFromPrivate(pk);
            const kpRectified = portedCrypto.keyPairFromPublic(portedCrypto.recoverPubKey(strHash, signature));

            assert.equal(kpRectified.address, kp.address);
            console.log(kp.address);
        });
    })

});
