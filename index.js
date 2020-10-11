require('dotenv').config();

const JupiterOneClient = require('@jupiterone/jupiterone-client-nodejs');
const axios = require('axios');
const chalk = require('chalk');
const dns = require('dns');
const sslCert = require('get-ssl-certificate-next');
const util = require('util');

const dnsLookup = util.promisify(dns.lookup);

const SCOPE = 'nslookup-shodan';
const HTTP_TIMEOUT = 1000; // 1sec

const {
  J1_ACCOUNT_ID: account,
  J1_API_TOKEN: accessToken,
  SHODAN_TOKEN: shodanToken,
} = process.env;

function printSyncJobReport(
  syncJob,
  propertyNames,
) {
  console.log('\nJ1 UPLOAD REPORT:\n');
  for (const propertyName of propertyNames) {
    if (propertyName.startsWith('num')) {
      const prettyName = propertyName
        .replace(/([a-z])([A-Z])/g, (match, p1, p2) => {
          return p1 + ' ' + p2;
        })
        .substring(3);
      console.log(
        `  ${chalk.bold(prettyName)} = ${syncJob[propertyName]}`
      );
    }
  }
  console.log('');
}

async function initializeJ1Client() {
  process.stdout.write(`Authenticating with JupiterOne account ${account}... `);
  const j1Client = await new JupiterOneClient({
    account,
    accessToken,
  }).init();
  console.log('OK');
  return j1Client;
}

async function main() {
  const j1Client = await initializeJ1Client();

  const hosts = [];
  const entities = [];
  const relationships = [];

  // Get DomainRecords that do not connect to an existing entity in graph
  const query = 
    `find DomainRecord with value!=undefined and type=('A' or 'AAAA' or 'CNAME') that !connects * with _scope!='${SCOPE}'`;
  const domainRecords = await j1Client.queryV1(query);

  // Lookup DNS record and get Shodan data on the target IP address
  const skippedItems = [];
  for (const item of domainRecords || []) {
    const entityId = item.entity._id;
    const entityKey = item.entity._key;
    const host = item.properties.value;
    if (host) {
      let address;
      try {
        const res = await dnsLookup(host);
        address = res.address;
      } catch (err) {
        console.error(`Skipped ${host}.`);
        console.error(err.toString());
        skippedItems.push(host);
      }

      if (address) {
        console.log('Working on DomainRecord:');
        console.log({ entityId, entityKey, host, address });

        const hostEntity = {
          _key: `discovered_host:${address}`,
          _type: `discovered_host`,
          _class: 'Host',
          displayName: address,
          publicIpAddress: address,
        };

        if (!hosts.includes(address)) {
          hosts.push(address);
        
          try {
            const res = await axios.get(`https://api.shodan.io/shodan/host/${address}?key=${shodanToken}`);
            const shodan = res.data;
            Object.assign(hostEntity, {
              hostname: shodan.hostnames,
              ports: shodan.ports,
              ASN: shodan.asn,
              ISP: shodan.isp,
              org: shodan.org,
              domain: shodan.domains,
              longitude: shodan.longitude,
              latitude: shodan.latitude,
              city: shodan.city,
              country: shodan.country_name,
              countryCode: shodan.country_code,
              regionCode: shodan.region_code,
              postalCode: shodan.postal_code,
              dmaCode: shodan.dma_code,
              os: shodan.os,
              tags: shodan.tags,
              // The certificate data from Shodan may not be accurate for shared hosting sites
              // certSubject: data.data.map(d => d.ssl?.cert?.subject?.CN).filter(d => !!d),
            });
          } catch (err) {
            console.error(err.toString());
          }

          // If the record points to a host with HTTPS enabled, try to get the certificate.
          if (hostEntity.ports?.includes(443)) {
            try {
              const cert = await sslCert.get(item.properties.name, HTTP_TIMEOUT, 443, 'https:', false);
              Object.assign(hostEntity, {
                certSubject: cert.subject.CN,
                certIssuer: cert.issuer.CN,
                certFingerprint: cert.fingerprint,
                certFingerprint256: cert.fingerprint256,
                certIssuedOn: cert.valid_from,
                certExpiresOn: cert.valid_to,
              });
            } catch (err) {
              console.error(err.toString());
            }
          }

          entities.push(hostEntity);
        }
        
        relationships.push({
          _key: `${entityKey}|connects|${hostEntity._key}`,
          _type: "domain_record_connects_discovered_host",
          _class: "CONNECTS",
          _fromEntityId: entityId,
          _fromEntityKey: entityKey,
          _toEntityKey: hostEntity._key,
          displayName: "CONNECTS",
        });
      }
    }
  }

  // Upload entities and relationships to JupiterOne
  const result = await j1Client.bulkUpload({
    scope: SCOPE,
    entities,
    relationships,
  });

  printSyncJobReport(result.finalizeResult.job, [
    'numEntitiesUploaded',
    'numRelationshipsUploaded',
  ]);

  if (skippedItems.length > 0) {
    console.log('The following records were skipped:');
    console.log(skippedItems);
  }
}

main();
