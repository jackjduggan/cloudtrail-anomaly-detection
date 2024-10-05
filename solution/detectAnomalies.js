const fs = require('fs');
const path = require('path');
var ipRangeCheck = require("ip-range-check");

let log_data = [];
const log_dir = 'cloudtrail_logs';
const log_files = [
    'cloudtrail_log_1.json',
    'cloudtrail_log_2.json',
    'cloudtrail_log_3.json',
    'cloudtrail_log_4.json',
    'cloudtrail_log_5.json',
    'cloudtrail_log_6.json',
    'cloudtrail_log_7.json',
    'cloudtrail_log_8.json',
    'cloudtrail_log_9.json',
    'cloudtrail_log_10.json',
]

// *** Potential Anomalies
// IP Address Range - high
const valid_IP_ranges = ["192.168.1.0/24", "10.0.0.0/16"];

// Root Account Usage - high
// Production EC2 modification - high
// Production S3 modification - high
// IAM User/Role modification - high

// detect anomalies function
function detectAnomalies(log_data) {
    let anomalies = [];

    log_data.forEach(log => {
        let anomaly = null;

        if (!ipRangeCheck(log.sourceIPAddress, valid_IP_ranges)) {
            risk_score = 'high';
            anomaly = `ANOMALY DETECTED (Unauthorized Source IP Address): ${JSON.stringify(log)}`;
        }
        

        if (anomaly) {
            anomalies.push( {anomaly, risk_score} );
        }
    });

    return anomalies;
}


log_files.forEach(file => {
    const filePath = path.join(log_dir, file);
    const file_data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    log_data = log_data.concat(file_data.Records) // appends each file's 'Records' to the log_data array
});
const anomalies = detectAnomalies(log_data);

anomalies.forEach(anom => console.log(`Risk Score: ${anom.risk_score}, Details: ${anom.anomaly}`));
