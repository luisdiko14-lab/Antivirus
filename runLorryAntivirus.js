const fs = require('fs');

// Load JSON file
const data = JSON.parse(fs.readFileSync('bigDataLorry.json', 'utf8'));

// Print some info
console.log("Lorry AntiVirus Version:", data.lorryAV.version);
console.log("Last Update:", data.lorryAV.lastUpdate);
console.log("Number of Threat Definitions:", data.lorryAV.definitions.length);

// List all threats
data.lorryAV.definitions.forEach(def => {
    console.log(`- ${def.name} [${def.severity}] discovered on ${def.discovered}`);
});

// Simulate a scan
console.log("\nStarting scan...");
data.lorryAV.scanSettings.scanTargets.forEach(target => {
    console.log(`Scanning ${target}...`);
});
console.log("Scan complete. No threats detected."); // placeholder
