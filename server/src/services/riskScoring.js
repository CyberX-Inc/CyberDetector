const calculateRisk = (results) => {
  let score = 0;
  const reasons = [];
  if (results.virusTotal && results.virusTotal.detected) {
    score += 50;
    reasons.push(results.virusTotal.message);
  }
  if (results.googleSafeBrowsing && results.googleSafeBrowsing.detected) {
    score += 50;
    reasons.push(results.googleSafeBrowsing.message);
  }
  if (results.urlhaus && results.urlhaus.detected) {
    score += 50;
    reasons.push(results.urlhaus.message);
  }
  if (results.localFindings) {
    for (const finding of results.localFindings) {
      score += finding.points;
      reasons.push(finding.check);
    }
  }
  const decision = score >= 60 ? 'block' : 'redirect';
  return { score, decision, reasons };
};
module.exports = { calculateRisk };
