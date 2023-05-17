
function logWithTimestamp(message, logger = console.log) {
  let currentDateTime = new Date();
  let formattedDateTime = currentDateTime.toLocaleString();
  logger(`${formattedDateTime} - ${message}`);
}

function testPattern(pattern, input, entityType) {
  let result = pattern.test(input);
  logWithTimestamp(`Tested ${entityType}: ${input}, Result: ${result}`);
  return result;
}

function isValidIPAddress(ipAddress) {
  let pattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  return testPattern(pattern, ipAddress, 'IP');
}

function isValidDomain(domain) {
  let pattern = /^(https?:\/\/)?((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,})(:\d+)?(\/[-a-z\d%_.~+]*)*(\?[;&a-z\d%_.~+=-]*)?(#[-a-z\d_]*)?$/;
  return testPattern(pattern, domain, 'domain');
}

function isValidHash(hash) {
  let pattern = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
  return testPattern(pattern, hash, 'hash');
}

function getInputType(input) {
  if (isValidIPAddress(input)) return 'ip';
  if (isValidDomain(input)) return 'url';
  if (isValidHash(input)) return 'hash';
  return 'unknown';
}

function formatDate(dateString) {
  if (dateString === 'N/A') return dateString;

  const date = new Date(dateString);

  if (isNaN(date.getTime())) {
    return 'Not Found';
  }

  const formatter = new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });

  return formatter.format(date);
}

function formatDateAge(dateString) {
  if (dateString === 'N/A') return dateString;

  const date = new Date(dateString);

  if (isNaN(date.getTime())) {
    return 'Invalid date';
  }

  const formatter = new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });

  const formattedDate = formatter.format(date);
  const age = calculateAge(date);

  return `${formattedDate} (${age} years old)`;
}


function calculateAge(date) {
  const now = new Date();
  const ageInMilliseconds = now - date;
  const ageInYears = ageInMilliseconds / (1000 * 60 * 60 * 24 * 365.25);
  return Math.floor(ageInYears);
}


async function fetchApi(url, headers) {
  try {
    const response = await fetch(url, { headers });
    const data = await response.json();
    return data;
  } catch (error) {
    console.error("Error fetching API data:", error);
  }
}



chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "apiCaller",
    title: "Perform OSINT",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "apiCaller") {
    chrome.storage.sync.get(
      [
        "virusTotalApiKey",
        "abuseIPDBApiKey",
        "threatJammerApiKey",
        "ibmXForceApiKey",
        "ipQualityScoreApiKey",
      ],
      (keys) => {
        let inputType = getInputType(info.selectionText);
        switch (inputType) {
          case "ip":
            handleIPClick(info.selectionText, keys);
            break;
          case "url":
            handleURLClick(info.selectionText, keys);
            break;
          case "hash":
            handleHashClick(info.selectionText, keys);
            break;
        }
      }
    );
  }
});
function copyToClipboard(result) {
  console.log("copyToClipboard called with result: ", result);
  
  let code = 'navigator.clipboard.writeText("' + result + '")';
  console.log("Generated code: ", code);
  
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    console.log("Active tabs: ", tabs);
    if (tabs.length > 0) {
      console.log("Injecting script into tab with ID: ", tabs[0].id);
      chrome.scripting.executeScript({
        target: {tabId: tabs[0].id},
        function: functionToInject,
        args: [result]
      });
    } else {
      console.error("No active tabs found.");
    }
  });
};

function functionToInject(result) {
  console.log("functionToInject called with result: ", result);
  
  navigator.clipboard.writeText(result).then(function() {
    console.log('Copying to clipboard was successful!');
  }, function(err) {
    console.error('Could not copy text: ', err);
  });
}

function showNotification(title, message, result) {
  chrome.storage.local.set({ notificationTitle: title, notificationMessage: message, clipboardText: result }, () => {
    chrome.windows.create({
      url: 'notification.html',
      type: 'popup',
      width: 300,
      height: 150
    });
  });
}

async function handleIPClick(selectionText, keys) {
  console.log("Start IP handling:", new Date().toLocaleString());
  let inputType = getInputType(selectionText);

  if (inputType !== "ip") {
    return;
  }

  let { virusTotalApiKey, abuseIPDBApiKey, threatJammerApiKey } = keys;
  let ip = selectionText;

  let virusTotalUrl = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;
  let abuseIPDBUrl = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`;
  let threatJammerUrl = `https://dublin.api.threatjammer.com/v1/assess/ip/${ip}`;

  let virusTotalHeaders = { "x-apikey": virusTotalApiKey };
  let abuseIPDBHeaders = { Key: abuseIPDBApiKey, Accept: "application/json" };
  let threatJammerHeaders = { Authorization: `Bearer ${threatJammerApiKey}`, Accept: "application/json" };

  let virusTotalData = fetchApi(virusTotalUrl, virusTotalHeaders);
  let abuseIPDBData = fetchApi(abuseIPDBUrl, abuseIPDBHeaders);
  let threatJammerData = fetchApi(threatJammerUrl, threatJammerHeaders);

  let data = await Promise.all([virusTotalData, abuseIPDBData, threatJammerData]);
  processIPData(data, ip);
}


// Function for processing and displaying IP data
function processIPData([virusTotalData, abuseIPDBData, threatJammerData], ip) {
  console.log("Start IP data processing:", new Date().toLocaleString());
  let harmless = 0;
  let malicious = 0;
  let undetected = 0;
  let virusTotalString = "VirusTotal: Not Found";
  let threatJammerString = "Threat Jammer: Not Found";
  let ipdbAbuseString = "IPDBAbuse: Not Found";
  let countryString = "Country: Not Found";
  let usageTypeString = "UsageType: Not Found";
  let domainString = "Domain: Not Found";

  if (virusTotalData.data && virusTotalData.data.attributes && virusTotalData.data.attributes.last_analysis_stats) {
    let stats = virusTotalData.data.attributes.last_analysis_stats;
    harmless = stats.harmless || 0;
    malicious = stats.malicious || 0;
    undetected = stats.undetected || 0;
    virusTotalString = `VirusTotal: ${malicious} / ${harmless + malicious + undetected}`;
  }

  if (threatJammerData.score && threatJammerData.reason) {
    threatJammerString = `Threat Jammer: ${threatJammerData.score || "No"} Risk Score - ${threatJammerData.reason}`;
  }

  if (abuseIPDBData.data && abuseIPDBData.data.abuseConfidenceScore) {
    ipdbAbuseString = `IPDBAbuse: Abuse confidence score ${abuseIPDBData.data.abuseConfidenceScore}`;
  }

  if (abuseIPDBData.data) {
    countryString = `Country: ${abuseIPDBData.data.countryName || "Data not available"}`;
    usageTypeString = `UsageType: ${abuseIPDBData.data.usageType || "Data not available"}`;
    domainString = `Domain: ${abuseIPDBData.data.domain || "Data not available"}`;
  }

  let outputString = `OSINT on IP: "${ip}"
- ${virusTotalString}
- ${threatJammerString}
- ${ipdbAbuseString}
ISP Info:
- ${countryString}
- ${usageTypeString}
- ${domainString}`;

  //copyToClipboard(outputString);

  showNotification('IP OSINT Complete', "Completed",outputString);
  console.log("End IP data processing:", new Date().toLocaleString());
}

async function handleURLClick(selectionText, keys) {
  console.log("Start URL handling:", new Date().toLocaleString());
  let inputType = getInputType(selectionText);

  if (inputType !== "url") {
    return;
  }

  let { virusTotalApiKey, ibmXForceApiKey, ipQualityScoreApiKey } = keys;
  let input = selectionText;

  let virusTotalApiUrl = `https://www.virustotal.com/api/v3/domains/${input}`;
  let ibmXForceApiUrl = `https://api.xforce.ibmcloud.com/api/url/${input}`;
  let ibmXForceWhoisApiUrl = `https://api.xforce.ibmcloud.com/api/whois/${input}`;
  let ipQualityScoreApiUrl = `https://www.ipqualityscore.com/api/json/url/${ipQualityScoreApiKey}/${input}`;

  let virusTotalHeaders = { "x-apikey": virusTotalApiKey };
  let ibmXForceHeaders = { accept: "application/json", Authorization: `Basic ${ibmXForceApiKey}` };

  let fetchVirusTotal = fetchApi(virusTotalApiUrl, virusTotalHeaders);
  let fetchIbmXForce = fetchApi(ibmXForceApiUrl, ibmXForceHeaders);
  let fetchIbmXForceWhois = fetchApi(ibmXForceWhoisApiUrl, ibmXForceHeaders);
  let fetchIpQualityScore = fetchApi(ipQualityScoreApiUrl);

  let data = await Promise.all([fetchVirusTotal, fetchIbmXForce, fetchIbmXForceWhois, fetchIpQualityScore]);
  processURLData(data, input);
}

function processURLData([virusTotalData, ibmData, ibmWhoisData, ipQualityScoreData], input) {
  console.log("Start URL data processing:", new Date().toLocaleString());

  let harmless = 0,
    malicious = 0,
    undetected = 0,
    total = 0;
  let virusTotalResult = "VirusTotal: Data not available";

  if (
    virusTotalData &&
    virusTotalData.data &&
    virusTotalData.data.attributes &&
    virusTotalData.data.attributes.last_analysis_stats
  ) {
    harmless = virusTotalData.data.attributes.last_analysis_stats.harmless || 0;
    malicious = virusTotalData.data.attributes.last_analysis_stats.malicious || 0;
    undetected = virusTotalData.data.attributes.last_analysis_stats.undetected || 0;
    total = harmless + malicious + undetected;
    virusTotalResult = `VirusTotal: ${malicious} / ${total}`;
  }


  let ibmXForceResult = "IBM X-Force: Not Found";
  if (ibmData && ibmData.result && ibmData.result.score) {
    ibmXForceResult = `IBM X-Force: Risk Score ${ibmData.result.score}`;
  }

  let ibmWhoisResult = 'IBM X-Force WHOIS: Data not available';
  if (ibmWhoisData) {
    const createdDate = formatDateAge(ibmWhoisData.createdDate) || 'N/A';
    const updatedDate = formatDate(ibmWhoisData.updatedDate) || 'N/A';
    const expiresDate = formatDate(ibmWhoisData.expiresDate) || 'N/A';
    const contactEmail = ibmWhoisData.contactEmail || 'N/A';
    const registrarName = ibmWhoisData.registrarName || 'N/A';
    let contactInfo = '';

    if (ibmWhoisData.contact && ibmWhoisData.contact.length > 0) {
      ibmWhoisData.contact.forEach((contact, index) => {
        const type = contact.type || 'N/A';
        const organization = contact.organization || 'N/A';
        const country = contact.country || 'N/A';

        contactInfo += `\n  Contact ${index + 1}:\n  - Type: ${type}\n  - Organization: ${organization}\n  - Country: ${country}`;
      });
    } else {
      contactInfo = '\n  No contact information available';
    }
    ibmWhoisResult = `IBM X-Force WHOIS: "${input}" \n- Created Date: ${createdDate}\n- Updated Date: ${updatedDate}\n- Expires Date: ${expiresDate}\n- Contact Email: ${contactEmail}\n- Registrar Name: ${registrarName}${contactInfo}`;
  }


  let ipQualityScoreResult = 'IPQualityScore: Data not available';
  if (ipQualityScoreData && ipQualityScoreData.success) {
    const unsafeStatus = ipQualityScoreData.unsafe ? 'Unsafe' : 'Clean';
    const categories = [];

    if (ipQualityScoreData.malware) categories.push('Malware');
    if (ipQualityScoreData.phishing) categories.push('Phishing');
    if (ipQualityScoreData.spamming) categories.push('Spamming');
    if (ipQualityScoreData.suspicious) categories.push('Suspicious');
    if (ipQualityScoreData.adult) categories.push('Adult Content');

    const categoriesStr = categories.length > 0 ? `(${categories.join(', ')})` : '';

    ipQualityScoreResult = `IPQualityScore: Risk Score ${ipQualityScoreData.risk_score} - Verdict: ${unsafeStatus} ${categoriesStr}`;
  }

  const header = `OSINT on URL: "${input}"`;
  const result = `${header}\n- ${virusTotalResult}\n- ${ibmXForceResult}\n- ${ipQualityScoreResult}\n\n${ibmWhoisResult}`;

 // copyToClipboard(result);
  showNotification('URL OSINT Complete', "Completed",result);
  console.log("End URL data processing:", new Date().toLocaleString());
}

async function handleHashClick(selectionText, keys) {
  console.log("Start Hash handling:", new Date().toLocaleString());
  let inputType = getInputType(selectionText);

  if (inputType !== "hash") {
    return;
  }

  let { virusTotalApiKey, ibmXForceApiKey } = keys;
  let input = selectionText;

  let virusTotalApiUrl = `https://www.virustotal.com/api/v3/files/${input}`;
  let ibmXForceApiUrl = `https://api.xforce.ibmcloud.com/api/malware/${input}`;

  let virusTotalHeaders = { "x-apikey": virusTotalApiKey };
  let ibmXForceHeaders = { accept: "application/json", Authorization: `Basic ${ibmXForceApiKey}` };

  let fetchVirusTotal = fetchApi(virusTotalApiUrl, virusTotalHeaders);
  let fetchIbmXForce = fetchApi(ibmXForceApiUrl, ibmXForceHeaders);

  let data = await Promise.all([fetchVirusTotal, fetchIbmXForce]);
  processHashData(data, input);
}

function processHashData([virusTotalData, ibmData], input) {
  console.log("Start Hash data processing:", new Date().toLocaleString());

      let harmless = 0,
      malicious = 0,
      undetected = 0,
      total = 0;
    let virusTotalResult = 'VirusTotal: Not Found';
    let threatLabel = '';
    let subCategories = '';
    if (
      virusTotalData &&
      virusTotalData.data &&
      virusTotalData.data.attributes &&
      virusTotalData.data.attributes.last_analysis_stats
    ) {
      const attributes = virusTotalData.data.attributes;
      const stats = attributes.last_analysis_stats;
      harmless = stats.harmless || 0;
      malicious = stats.malicious || 0;
      undetected = stats.undetected || 0;
      total = harmless + malicious + undetected;
      virusTotalResult = `VirusTotal: ${malicious} / ${total}`;
      if (attributes.popular_threat_classification) {
        const classification = attributes.popular_threat_classification;
        if (classification.suggested_threat_label) {
          threatLabel = `Threat Label (VT): ${classification.suggested_threat_label}`;
        }

        if (classification.popular_threat_category) {
          subCategories = 'Subcategories (VT):';
          classification.popular_threat_category.forEach(category => {
            subCategories += ` ${category.value} (${category.count}),`;
          });
          subCategories = subCategories.slice(0, -1); 
        }
      }
    }


    let ibmXForceResult = 'IBM X-Force: Not Found';
    if (ibmData && ibmData.malware) {
      const malware = ibmData.malware;
      const external = malware.external;

      const variant = malware.family ? malware.family.join(', ') : 'Unknown';
      const type = external && external.malwareType ? external.malwareType : 'Unknown';
      const risk = malware.risk ? malware.risk : 'Unknown';
      const detectionCoverage = external && external.detectionCoverage ? external.detectionCoverage : 'Unknown';

      ibmXForceResult = `IBM X-Force: Risk ${risk}`;
    }
  
  const header = `OSINT on HASH: "${input}"`;
  const result = `${header}\n- ${virusTotalResult} ${threatLabel}\n- ${ibmXForceResult}`;

 // copyToClipboard(result);
  showNotification('HASH OSINT Complete', "Completed",result);
  console.log("End Hash data processing:", new Date().toLocaleString());
}