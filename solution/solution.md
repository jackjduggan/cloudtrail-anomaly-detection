# Cloudtrail Solution - Jack Duggan

### Approach

I defined a few steps as to how I wanted to approach this challenge:
1. Parse JSON data from multiple files into one data source.
2. Become familiar with the data structure and company security policy and think about possible anomalies.
3. Implement logic to check for anomalies such as IP violations, production resource modification, IAM modification and more.
4. Loop through each log in data source and apply checks, identifying anomalies and assigning an appropriate risk score. If any condition matches, push the anomaly to an anomalies array.
5. Format anomalies into JSON output.

### Assumptions
- I assumed that modification (mainly deletion) of S3 bucket contents is considered 'bucket modification', not just modification of the bucket itself.
- I assumed that *any* access whatsoever from outside the approved IP ranges was in violation of the security policy.
- The policy states that creation of IAM users is forbidden, but it also lists 'changes to IAM policies or roles' and 'creation or deletion of IAM users' under 'anomaly detection', so I grouped them all together as IAM violations.

### How I Assigned Risk Scores

| Anomaly Type      | Score | Reason
| ----------- | ----------- | ----------- |
| IP Address Range Violation    | High | Accessing resources from IP addresses outside range is in direct violation of security policy
| Usage of Root Account         | High | Root account activity is strictly prohibited
| Prod EC2 Modification         | High | Modifying production EC2 instances can have serious impacts on critical systems, particularly instance termination
| Prod S3 Modification          | High | Modifying production S3 buckets can have serious impacts on critical systems, particularly bucket modifcation or object removal
| IAM User/Role Modification    | High | Changes to IAM users/roles is prohibited as per the security policy
| Use of Unapproved AWS Services | High | Use of any unapproved AWS services requires a security review and written approval from the security team

I struggled to justify giving any of these anomalies anything less than a **high** score, especially considering many anomalies violated more than one of the security policy recommendations.