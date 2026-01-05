import QRCode from 'qrcode';

const otpAuthUrl = process.argv[2];

if (!otpAuthUrl) {
  throw new Error('Pass otpAuthUrl as argument');
}

async function main() {
  await QRCode.toFile('totp.png', otpAuthUrl);
  console.log('Saved QR Code');
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
