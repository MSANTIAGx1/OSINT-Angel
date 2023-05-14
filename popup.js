
function setInputValues(virusTotalApiKey, abuseIPDBApiKey, threatJammerApiKey, ibmXForceApiKey, ipQualityScoreApiKey) {
    document.getElementById('virus-total-api-key').value = virusTotalApiKey || '';
    document.getElementById('abuse-ipdb-api-key').value = abuseIPDBApiKey || '';
    document.getElementById('threat-jammer-api-key').value = threatJammerApiKey || '';
    document.getElementById('ibm-xforce-api-key').value = ibmXForceApiKey || '';
    document.getElementById('ip-quality-score-api-key').value = ipQualityScoreApiKey || '';
  }
  

  chrome.storage.local.get(['virusTotalApiKey', 'abuseIPDBApiKey', 'threatJammerApiKey', 'ibmXForceApiKey', 'ipQualityScoreApiKey'], (keys) => {
    setInputValues(keys.virusTotalApiKey, keys.abuseIPDBApiKey, keys.threatJammerApiKey, keys.ibmXForceApiKey, keys.ipQualityScoreApiKey);
  });
  

  document.getElementById('api-keys-form').addEventListener('submit', (e) => {
    e.preventDefault();
  
    const virusTotalApiKey = document.getElementById('virus-total-api-key').value;
    const abuseIPDBApiKey = document.getElementById('abuse-ipdb-api-key').value;
    const threatJammerApiKey = document.getElementById('threat-jammer-api-key').value;
    const ibmXForceApiKey = document.getElementById('ibm-xforce-api-key').value;
    const ipQualityScoreApiKey = document.getElementById('ip-quality-score-api-key').value;
  
    chrome.storage.local.set({
      virusTotalApiKey,
      abuseIPDBApiKey,
      threatJammerApiKey,
      ibmXForceApiKey,
      ipQualityScoreApiKey,
    });
  });
