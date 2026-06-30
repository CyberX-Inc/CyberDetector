const runLocalChecks = (urlString) => {
  const findings = [];
  let url;
  try {
    url = new URL(urlString);
  } catch (_) {
    findings.push({ check: 'Invalid URL', points: 0 });
    return findings;
  }
  const hostname = url.hostname;
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  if (ipv4Regex.test(hostname) || ipv6Regex.test(hostname)) {
    findings.push({ check: 'IP address used instead of domain', points: 10 });
  }
  if (urlString.length > 150) {
    findings.push({ check: 'URL length > 150', points: 10 });
  }
  if (urlString.includes('@')) {
    findings.push({ check: 'URL contains "@"', points: 15 });
  }
  const suspiciousTLDs = ['.zip', '.top', '.xyz', '.loan', '.men', '.click', '.date', '.party', '.win', '.bid', '.trade', '.webcam', '.science', '.download', '.review', '.vip', '.work', '.red', '.ooo', '.lol', '.mom', '.gdn', '.网址', '.sexy', '.kim', '.在线', '.中文网'];
  const tld = url.hostname.split('.').pop();
  if (suspiciousTLDs.some(sTLD => tld === sTLD || tld.endsWith(sTLD))) {
    findings.push({ check: `Suspicious TLD: .${tld}`, points: 10 });
  }
  const shorteners = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 't.co', 'tiny.cc',
    'tr.im', 'v.gd', 'cutt.ly', 'dub.sh', 'git.io', 'migre.me', 'tiny.pl', 'qr.net', 'snipurl.com', 'shorturl.at'
  ];
  if (shorteners.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
    findings.push({ check: 'URL shortener detected', points: 10 });
  }
  return findings;
};
module.exports = { runLocalChecks };
