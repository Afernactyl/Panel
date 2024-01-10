const axios = require('axios');
const { Theme, license, debug } = require('../../../../settings.json');

let lastExpirationDate = null;

async function checkLicense(licenseKey) {
  try {
    const response = await axios.get(`http://103.178.158.190:1447/v`, {
      headers: {
        Authorization: licenseKey,
      },
    });

    const { licenseKey: serverLicenseKey, expiration_date, blacklisted, reason } = response.data;

    // Only print the message if the expiration date changes
    if (expiration_date !== lastExpirationDate) {
      console.log(`_________________________________________`);
      console.log();
      console.log(`Afernactyl BETA 0.1 UNDER DEVELOPMENT MOD`);
      console.log(`RUNNING ON: ${Theme.port}`);
      console.log(`API STATUS: ONLINE`);
      console.log(`LICENSE EXPIRE: ${expiration_date}`);
      console.log(`_________________________________________`);
      lastExpirationDate = expiration_date;

      // Add your logic here based on the server's response
    }
  } catch (error) {
    console.log(`_________________________________________`);
    console.log();
    console.log(`Afernactyl BETA 0.1 UNDER DEVELOPMENT MOD`);
    if (error.response && error.response.data) {
      const { blacklisted, reason } = error.response.data;
      if (blacklisted) {
        console.log();
        console.log(`LICENSE BLACKLISTED`);
        console.log();
        console.log(`REASON: ${reason}`);
      } else {
        console.log(`INVALID LICENSE`);
      }
    } else {
      console.log(`API STATUS: OFFLINE`);
      console.log(`LICENSE EXPIRE: ${lastExpirationDate || 'Not available'}`);
    }
    console.log(`_________________________________________`);
    process.exit(0);

  if (debug===true) {throw error}
  }
}
// Example usage:
const licenseKey = license.key;
checkLicense(licenseKey);

// Check the license every 10 seconds
const intervalInMilliseconds = 15 * 60 * 1000; // 15 minutes
setInterval(() => {
  checkLicense(licenseKey);
}, intervalInMilliseconds);