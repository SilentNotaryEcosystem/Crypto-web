const portedCrypto = require('./src/port-crypto');

main().then(() => {
    process.exit(0);
}).catch((error) => {
    console.error(error);
    process.exit(1);
});
async function main(){
    const pk = 'd'.repeat(64);
    const pass = 'blah-blah';
    const objResult = await portedCrypto.encrypt(pass, pk);
    console.log(JSON.stringify(objResult));
    
}
