const fs = require('fs');
const path = require('path');
const ipRangeCheck = require("ip-range-check");
const geoip = require('geoip-country');

let log_data = [];
const log_dir = "cloudtrail_logs";
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
const valid_IP_ranges = ["192.168.1.0/24", "10.0.0.0/16"];

// detect anomalies function
function detectAnomalies(log_data) {
    let anomalies = [];

    log_data.forEach(log => {
        let anomaly = {
            "userName": log.userIdentity.userName,
            "userType": log.userIdentity.type,
            "eventSource": log.eventSource,
            "eventName": log.eventName,
            "awsRegion": log.awsRegion,
            "sourceIPAddress": log.sourceIPAddress,
            "sourceGeolocation": getCountryFromIP(log.sourceIPAddress),
            "riskLevel": null
        }
        let anomaly_detected = false;

        if (!ipRangeCheck(log.sourceIPAddress, valid_IP_ranges)) {
            anomaly.riskLevel = "high";
            anomaly_detected = true;
        }

        // root usage
        if (log.userIdentity.userName == "root") {
            anomaly.riskLevel = "high";
            anomaly_detected = true;
        }

        // production ec2 modification
        const ec2_actions = ["RunInstances", "StartInstances", "StopInstances", "TerminateInstances"];
        if (log.requestParameters && log.requestParameters.instancesSet && log.requestParameters.instancesSet.items) { // null checks for each level
            if (ec2_actions.includes(log.eventName)) {
                log.requestParameters.instancesSet.items.forEach(instance => {
                    if (instance.instanceId.includes("prod")) {
                        anomaly.riskLevel = "high";
                        anomaly_detected = true;
                    }
                })
            }
        }

        // Amazon S3 (Bucket deletion or duplication in production is strictly prohibited without prior approval)
        const s3_actions = ["CreateBucket",
                            "DeleteBucket",
                            "DeleteObject",
                            //"PutObject"
                            ];

        if (s3_actions.includes(log.eventName)) {
            if (log.requestParameters && log.requestParameters.bucketName) {
                if (log.requestParameters.bucketName.includes("prod")) {
                    anomaly.riskLevel = "high";
                    anomaly_detected = true;
                }
            }
        }

        // iam
        const iam_actions = ["CreateUser", "DeleteUser", "UpdateUser", "CreateRole", "DeleteRole", "UpdateRole"];
        if (iam_actions.includes(log.eventName)) {
            anomaly.riskLevel = "high";
            anomaly_detected = true;
        }

        const approved_aws_services = [
            "lambda.amazonaws.com",
            "dynamodb.amazonaws.com",
            "s3.amazonaws.com",
            "monitoring.amazonaws.com",
            "secretsmanager.amazonaws.com",
            "ecs.amazonaws.com"];
        if (!approved_aws_services.includes(log.eventSource)) {
            anomaly.riskLevel = "high";
            anomaly_detected = true;
        }
        
        if (anomaly_detected) {
            anomalies.push(anomaly);
        }
    });

    return anomalies;
}

function getCountryFromIP(ip_addr) {
    var geo = geoip.lookup(ip_addr);
    if (geo) {
        return {
            name: geo.name,
            continent: geo.continent_name
        }
    } else {
        return {
            name: 'Unknown',
            continent: 'Unknown'
        }
    }
}

function saveToFile(anomalies, file_path) {
    const jsonContent = JSON.stringify(anomalies, null, 2);  // json indentation formatting
    fs.writeFileSync(file_path, jsonContent, 'utf8');
}

function generateReport(anomalies) {
    saveToFile(anomalies, "./report.json")
}

log_files.forEach(file => {
    const filePath = path.join(log_dir, file);
    const file_data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

    log_data = log_data.concat(file_data.Records) // appends each file's 'Records' to the log_data array
});
const anomalies = detectAnomalies(log_data);
generateReport(anomalies)