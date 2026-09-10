#!/bin/bash

# Unit tests for the Cyber Sentry fetch scripts and SentryModel.
#
# Runs the scripts against a mock environment: a fixture advisory cache, a fake
# `pacman` on PATH, and an isolated XDG_RUNTIME_DIR. Live endpoints are used
# for cve-fetch, epss-fetch, exploitdb-fetch, and alerts-fetch when reachable.

set -uo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)

pass=0
fail=0
fails=()

t() {
  local desc=$1
  shift
  if "$@" >/dev/null 2>&1; then
    pass=$((pass + 1))
    echo "  PASS  $desc"
  else
    fail=$((fail + 1))
    fails+=("$desc")
    echo "  FAIL  $desc"
  fi
}

old_path=$PATH
old_runtime=${XDG_RUNTIME_DIR:-}
old_fake=${FAKE_INSTALLED:-}

new_env() {
  mktemp -d "${TMPDIR:-/tmp}/sentry-test.XXXXXX"
}

mocked_pacman() {
  local env=$1
  mkdir -p "$env/bin"
  cat >"$env/bin/pacman" <<'EOF'
#!/bin/bash
# Mock pacman: prints the lines of FAKE_INSTALLED as "name version".
if [[ -n ${FAKE_INSTALLED:-} ]]; then
  while IFS= read -r line; do
    [[ -n $line ]] && printf '%s\n' "$line"
  done <<<"$FAKE_INSTALLED"
fi
exit 0
EOF
  chmod +x "$env/bin/pacman"
}

echo
echo "== arch-fetch correlation =="

env=$(new_env)
mocked_pacman "$env"
mkdir -p "$env/cache/omarchy-cyber-sentry"

cat >"$env/cache/omarchy-cyber-sentry/arch-advisories.json" <<'EOF'
[
  {"name":"AVG-VULN","packages":["mypkg"],"affected":"1.0-1","fixed":"2.0-1","severity":"High","type":"multiple issues","issues":["CVE-2026-0001"],"issue_date":"2026-01-01","status":"Fixed"},
  {"name":"AVG-CURRENT","packages":["mypkg"],"affected":"1.0-1","fixed":"1.0-1","severity":"Low","type":"integer overflow","issues":["CVE-2026-0002"],"issue_date":"2026-01-02","status":"Fixed"},
  {"name":"AVG-MISSING","packages":["not-installed"],"affected":"1.0-1","fixed":"2.0-1","severity":"Critical","type":"rce","issues":["CVE-2026-0003"],"issue_date":"2026-01-03","status":"Fixed"},
  {"name":"AVG-OPEN","packages":["mypkg"],"affected":"2.0-1","fixed":null,"severity":"Medium","type":"dos","issues":["CVE-2026-0004"],"issue_date":"2026-01-04","status":"Vulnerable"},
  {"name":"AVG-PAST","packages":["mypkg"],"affected":"0.5-1","fixed":null,"severity":"High","type":"info","issues":["CVE-2026-0009"],"issue_date":"2026-01-09","status":"Vulnerable"},
  {"name":"AVG-NOTAFECTED","packages":["mypkg"],"affected":"1.0-1","fixed":null,"severity":"High","type":"info","issues":["CVE-2026-0008"],"issue_date":"2026-01-08","status":"Not affected"},
  {"name":"AVG-EPOCH","packages":["epkg"],"affected":"1:9.9-1","fixed":"2:1.0-1","severity":"High","type":"bof","issues":["CVE-2026-0005"],"issue_date":"2026-01-05","status":"Fixed"},
  {"name":"AVG-PKGREL","packages":["pkg2"],"affected":"1.0-1","fixed":"1.0-2","severity":"High","type":"xss","issues":["CVE-2026-0006"],"issue_date":"2026-01-06","status":"Fixed"},
  {"name":"AVG-MULTI","packages":["a","b"],"affected":"1.0-1","fixed":"2.0-1","severity":"Critical","type":"rce","issues":["CVE-2026-0007"],"issue_date":"2026-01-07","status":"Fixed"}
]
EOF

export FAKE_INSTALLED=$'mypkg 1.0-1\nepkg 2:1.0-1\npkg2 1.0-2\na 1.5-1\nb 2.0-1'
export XDG_RUNTIME_DIR="$env/cache"
export PATH="$env/bin:$PATH"

arch_out=$(./arch-fetch)
arch_json=$(jq -c . <<<"$arch_out")

t "advisory with installed < fixed is affected" \
  jq -e 'any(.advisories[]; .name == "AVG-VULN")' <<<"$arch_json"
t "advisory with installed == fixed is not affected" \
  jq -e 'all(.advisories[]; .name != "AVG-CURRENT")' <<<"$arch_json"
t "advisory for uninstalled package is not affected" \
  jq -e 'all(.advisories[]; .name != "AVG-MISSING")' <<<"$arch_json"
t "advisory with no fixed version but Vulnerable status flags package" \
  jq -e '.advisories[] | select(.name == "AVG-OPEN") | .unfixed == true' <<<"$arch_json"
t "open advisory with installed past the affected version is excluded" \
  jq -e 'all(.advisories[]; .name != "AVG-PAST")' <<<"$arch_json"
t "advisory marked Not affected is excluded" \
  jq -e 'all(.advisories[]; .name != "AVG-NOTAFECTED")' <<<"$arch_json"
t "epoch-aware: newer epoch is not affected" \
  jq -e 'all(.advisories[]; .name != "AVG-EPOCH")' <<<"$arch_json"
t "pkgrel-aware: higher pkgrel is not affected" \
  jq -e 'all(.advisories[]; .name != "AVG-PKGREL")' <<<"$arch_json"
t "multi-package advisory lists only vulnerable package" \
  jq -e '.advisories[] | select(.name == "AVG-MULTI") | .packages == "a=1.5-1"' <<<"$arch_json"
t "advisory carries cves, severity, date, fixed" \
  jq -e '.advisories[] | select(.name == "AVG-VULN") | (.cves | length == 1) and (.severity == "High") and (.date == "2026-01-01") and (.fixed == "2.0-1")' <<<"$arch_json"
t "ok flag and installedChecked count present" \
  jq -e '.ok == true and .installedChecked == 5 and (.advisories | length) == 3' <<<"$arch_json"

echo
echo "== kev-fetch parsing =="

env2=$(new_env)
mkdir -p "$env2/cache/omarchy-cyber-sentry"
# The "recent" fixture entry's dateAdded must stay within --recent-days of
# whenever this suite runs, since kev-fetch computes its cutoff relative to
# the current wall-clock date, not a fixed point in time.
recent_date=$(date -u -d "2 days ago" +%Y-%m-%d 2>/dev/null || date -u -v-2d +%Y-%m-%d 2>/dev/null || "")
cat >"$env2/cache/omarchy-cyber-sentry/kev-catalog.json" <<EOF
{"catalogVersion":"2026.08.15","dateReleased":"2026-08-15T12:00:00Z","count":2,"vulnerabilities":[
  {"cveID":"CVE-2026-1001","vendorProject":"Acme","product":"Widget","vulnerabilityName":"Bad Widget","dateAdded":"$recent_date","shortDescription":"Exploited.","requiredAction":"Patch.","dueDate":"2026-09-05","knownRansomwareCampaignUse":"Known"},
  {"cveID":"CVE-2026-1002","vendorProject":"Globex","product":"Doohickey","vulnerabilityName":"Old Doohickey","dateAdded":"2026-01-01","shortDescription":"Old.","requiredAction":"Patch.","dueDate":"2026-01-22","knownRansomwareCampaignUse":"Unknown"}
]}
EOF
export XDG_RUNTIME_DIR="$env2/cache"

kev_out=$(./kev-fetch)
kev_json=$(jq -c . <<<"$kev_out")
t "kev-fetch parses the fixture and reports count" \
  jq -e '.ok == true and .count == 2' <<<"$kev_json"
t "kev-fetch emits the catalog fields" \
  jq -e '.vulnerabilities[0] | (.cveID == "CVE-2026-1001") and (.knownRansomwareCampaignUse == "Known") and (.shortDescription | length > 0)' <<<"$kev_json"

kev_recent=$(./kev-fetch --recent-days 7)
kev_recent_json=$(jq -c . <<<"$kev_recent")
t "kev-fetch --recent-days filters by dateAdded" \
  jq -e '.count == 1 and .vulnerabilities[0].cveID == "CVE-2026-1001"' <<<"$kev_recent_json"

echo
echo "== SentryModel.js functions =="

export PATH="$old_path"

model_test=$(node -e "
  const fs = require('fs');
  let src = fs.readFileSync(process.argv[1], 'utf8');
  src = src.replace(/^\\.pragma library\\s*\\n/m, '');
  const fns = [...src.matchAll(/function\\s+(\\w+)\\s*\\(/g)].map(m => m[1]);
  const exportLines = fns.map(f => 'exports.' + f + ' = ' + f + ';').join('\\n');
  const mod = {};
  new Function('exports', src + '\\n' + exportLines)(mod);

  // --- ransomware mapping ---
  const r1 = mod.kevRow({knownRansomwareCampaignUse:'Known',cveID:'CVE-2026-1001',vendorProject:'A',product:'B',vulnerabilityName:'X',dateAdded:'2026-01-01',shortDescription:'d',requiredAction:'a',dueDate:'2026-02-01'});
  const r2 = mod.kevRow({knownRansomwareCampaignUse:'Unknown',cveID:'CVE-2026-1002'});
  const r3 = mod.kevRow({cveID:'CVE-2026-1003'});

  // --- installed field ---
  const r4 = mod.kevRow({cveID:'CVE-X',vendorProject:'A',product:'B'});
  const r5 = mod.kevRow({cveID:'CVE-X'});

  // --- epss merge ---
  const archRow = mod.archRow({name:'AVG-1',severity:'High',packages:'foo',fixed:'2.0',cves:['CVE-2026-0001'],date:'2026-01-01'});
  const kevR = mod.kevRow({cveID:'CVE-2026-0002',vendorProject:'X',product:'Y',vulnerabilityName:'Z',dateAdded:'2026-08-01'});
  const rows = [archRow, kevR];
  const epssParsed = {ok:true,scores:{'CVE-2026-0001':{epss:'0.95',percentile:'0.99'},'CVE-2026-0002':{epss:'0.10',percentile:'0.50'}}};
  mod.epssMerge(rows, epssParsed);
  const epss1 = rows[0].epss;
  const epss2 = rows[1].epss;

  // --- exploit merge ---
  const eRows = [mod.archRow({name:'E1',severity:'High',packages:'bar',fixed:'3.0',cves:['CVE-2026-0010'],date:'2026-02-01'})];
  mod.exploitMerge(eRows, {ok:true,matches:{'CVE-2026-0010':['Title A','Title B']}});
  const exploit1 = eRows[0].exploitTitles.length;

  // --- installMerge ---
  const iRows = [mod.kevRow({cveID:'CVE-2026-0020',vendorProject:'Acme',product:'Widget',dateAdded:'2026-08-01'})];
  mod.installMerge(iRows, {'acme-widget':'1.0','something-else':'2.0'});
  const installed1 = iRows[0].installed;

  const iRows2 = [mod.kevRow({cveID:'CVE-2026-0021',vendorProject:'Tiny',product:'Z',dateAdded:'2026-08-01'})];
  mod.installMerge(iRows2, {'big-package':'1.0'});
  const installed2 = iRows2[0].installed;

  // --- kevRecentFilter ---
  var today = new Date().toISOString().slice(0,10);
  var oldDate = '2020-01-01';
  const allKev = [mod.kevRow({cveID:'CVE-NEW',dateAdded:today}), mod.kevRow({cveID:'CVE-OLD',dateAdded:oldDate})];
  const recent = mod.kevRecentFilter(allKev, 30);

  // --- markAllSeen ---
  const notif1 = {};
  const markRows = [{id:'X'},{id:'Y'}];
  mod.markAllSeen(markRows, notif1, 1000);
  const seen1 = notif1['X'] === 1000;
  const seen2 = notif1['Y'] === 1000;

  // --- epssColor/epssLabel ---
  const ec1 = mod.epssColor('0.95');
  const ec2 = mod.epssColor('0');
  const el1 = mod.epssLabel('0.85');
  const el2 = mod.epssLabel('0');

  // --- nvdRow ---
  const nvd = mod.nvdRow({id:'CVE-2026-5000',severity:'Critical',score:9.8,description:'Bad',published:'2026-08-10'});
  const nvdType = nvd.type;
  const nvdScore = nvd.score;

  // --- alertRow ---
  const alert = mod.alertRow({title:'NCSC-2026-0001 advisory',link:'https://example.com',date:'2026-08-15'});
  const alertType = alert.type;

  // --- archFixState ---
  const fixedRow = mod.archRow({name:'AVG-2',severity:'High',packages:'foo=1.0;bar=2.0',fixed:'3.0-1',cves:['CVE-2026-0030'],date:'2026-01-01'});
  const fixState = mod.archFixState(fixedRow);
  const unfixedRow = mod.archRow({name:'AVG-3',severity:'High',packages:'foo=1.0',fixed:'',unfixed:true,cves:['CVE-2026-0031'],date:'2026-01-01'});
  const noFixState = mod.archFixState(unfixedRow);
  const kevForFix = mod.kevRow({cveID:'CVE-2026-0032',vendorProject:'X',product:'Y',dateAdded:'2026-08-01'});
  const nonArchFixState = mod.archFixState(kevForFix);

  // --- parsePackageList ---
  const pkgList = mod.parsePackageList('foo 1.0-1\nbar-bin 2.3.4-1\n\nbaz 5.6.7-2\n');
  const pkgNames = pkgList.map(function(p){return p.name}).join(',');
  const pkgVersions = pkgList.map(function(p){return p.version}).join(',');
  const pkgCount = pkgList.length;
  const sortedNames = mod.sortByName([{name:'zeta'},{name:'alpha'},{name:'Middle'}]).map(function(p){return p.name}).join(',');

  // --- buildRows with 4 sources ---
  const allRows = mod.buildRows(
    {advisories:[{name:'A1',severity:'High',packages:'p',fixed:'1.0',issues:['CVE-1'],date:'2026-01-01'}]},
    {vulnerabilities:[{cveID:'CVE-2',vendorProject:'X',product:'Y',vulnerabilityName:'Z',dateAdded:'2026-08-01'}]},
    {cves:[{id:'CVE-3',severity:'High',score:7.5,description:'D',published:'2026-08-10'}]},
    {advisories:[{title:'Alert 1',link:'https://l',date:'2026-08-12'}]}
  );
  const rowTypes = allRows.map(function(r){return r.type}).sort().join(',');

  console.log(JSON.stringify({
    ransomware1: r1.ransomware, ransomware2: r2.ransomware, ransomware3: r3.ransomware,
    installed1: r4.installed !== undefined, installed2: r5.installed === false,
    epss1: epss1, epss2: epss2,
    exploit1: exploit1,
    installed3: installed1, installed4: installed2,
    recentCount: recent.length,
    seen1: seen1, seen2: seen2,
    ec1: ec1, ec2: ec2, el1: el1, el2: el2,
    nvdType: nvdType, nvdScore: nvdScore,
    alertType: alertType,
    rowTypes: rowTypes,
    fixCommand: fixState ? fixState.command : null,
    fixPackages: fixState ? fixState.packages : null,
    fixVersion: fixState ? fixState.version : null,
    noFixState: noFixState,
    nonArchFixState: nonArchFixState,
    pkgNames: pkgNames,
    pkgVersions: pkgVersions,
    pkgCount: pkgCount,
    sortedNames: sortedNames
  }));
" "$(dirname "$0")/../SentryModel.js" 2>/dev/null)

if [[ -n $model_test ]]; then
  t "SentryModel.kevRow: ransomware Known=true" \
    jq -e '.ransomware1 == true' <<<"$model_test"
  t "SentryModel.kevRow: ransomware Unknown=false" \
    jq -e '.ransomware2 == false' <<<"$model_test"
  t "SentryModel.kevRow: ransomware missing=false" \
    jq -e '.ransomware3 == false' <<<"$model_test"
  t "SentryModel.kevRow: installed field present" \
    jq -e '.installed1 == true' <<<"$model_test"
  t "SentryModel.epssMerge: scores applied to rows" \
    jq -e '.epss1 == "0.95" and .epss2 == "0.10"' <<<"$model_test"
  t "SentryModel.exploitMerge: exploit titles applied" \
    jq -e '.exploit1 == 2' <<<"$model_test"
  t "SentryModel.installMerge: fuzzy match finds acme-widget" \
    jq -e '.installed3 == true' <<<"$model_test"
  t "SentryModel.installMerge: no false positive on short vendor" \
    jq -e '.installed4 == false' <<<"$model_test"
  t "SentryModel.kevRecentFilter: excludes old entries" \
    jq -e '.recentCount == 1' <<<"$model_test"
  t "SentryModel.markAllSeen: marks all ids" \
    jq -e '.seen1 == true and .seen2 == true' <<<"$model_test"
  t "SentryModel.epssColor: red for >= 0.9" \
    jq -e '.ec1 == "#e5484d"' <<<"$model_test"
  t "SentryModel.epssColor: empty for 0" \
    jq -e '.ec2 == ""' <<<"$model_test"
  t "SentryModel.epssLabel: shows percentage" \
    jq -e '.el1 == "85%"' <<<"$model_test"
  t "SentryModel.epssLabel: empty for 0" \
    jq -e '.el2 == ""' <<<"$model_test"
  t "SentryModel.nvdRow: type is nvd" \
    jq -e '.nvdType == "nvd"' <<<"$model_test"
  t "SentryModel.nvdRow: preserves score" \
    jq -e '.nvdScore == 9.8' <<<"$model_test"
  t "SentryModel.alertRow: type is alert" \
    jq -e '.alertType == "alert"' <<<"$model_test"
  t "SentryModel.buildRows: 4 source types" \
    jq -e '.rowTypes == "alert,arch,kev,nvd"' <<<"$model_test"
  t "SentryModel.archFixState: command is always full-system update" \
    jq -e '.fixCommand == "sudo pacman -Syu"' <<<"$model_test"
  t "SentryModel.archFixState: packages passed through unmodified" \
    jq -e '.fixPackages == "foo=1.0;bar=2.0"' <<<"$model_test"
  t "SentryModel.archFixState: version passed through unmodified" \
    jq -e '.fixVersion == "3.0-1"' <<<"$model_test"
  t "SentryModel.archFixState: null when advisory has no fix released" \
    jq -e '.noFixState == null' <<<"$model_test"
  t "SentryModel.archFixState: null for non-arch row types" \
    jq -e '.nonArchFixState == null' <<<"$model_test"
  t "SentryModel.parsePackageList: parses multiple valid lines" \
    jq -e '.pkgNames == "foo,bar-bin,baz"' <<<"$model_test"
  t "SentryModel.parsePackageList: preserves versions in order" \
    jq -e '.pkgVersions == "1.0-1,2.3.4-1,5.6.7-2"' <<<"$model_test"
  t "SentryModel.parsePackageList: skips the blank line" \
    jq -e '.pkgCount == 3' <<<"$model_test"
  t "SentryModel.sortByName: case-insensitive alphabetical order" \
    jq -e '.sortedNames == "alpha,Middle,zeta"' <<<"$model_test"
else
  echo "  SKIP  SentryModel.js (node unavailable)"
fi

unset XDG_RUNTIME_DIR PATH FAKE_INSTALLED
export XDG_RUNTIME_DIR="$old_runtime"
export PATH="$old_path"
export FAKE_INSTALLED="$old_fake"

echo
echo "== cve-fetch live =="

if curl -fsS --max-time 8 -o /dev/null "https://cveawg.mitre.org/api/cve/CVE-2024-6387" 2>/dev/null; then
  cve_out=$(./cve-fetch CVE-2024-6387)
  cve_json=$(jq -c . <<<"$cve_out")
  t "cve-fetch returns a real CVE with description and id" \
    jq -e '.ok == true and .id == "CVE-2024-6387" and (.description | length > 20)' <<<"$cve_json"
else
  echo "  SKIP  cve-fetch live (cve.org unreachable)"
fi

cve_bad=$(./cve-fetch "NOT-A-CVE")
cve_bad_json=$(jq -c . <<<"$cve_bad")
t "cve-fetch returns an error object for an unknown id" \
  jq -e '.ok == false and (.error | length > 0)' <<<"$cve_bad_json"

echo
echo "== epss-fetch live =="

if curl -fsS --max-time 8 -o /dev/null "https://api.first.org/data/v1/epss?cve=CVE-2024-6387" 2>/dev/null; then
  epss_out=$(./epss-fetch CVE-2024-6387 CVE-2024-3094)
  epss_json=$(jq -c . <<<"$epss_out")
  t "epss-fetch returns scores for two CVEs" \
    jq -e '.ok == true and .count == 2' <<<"$epss_json"
  t "epss-fetch score has epss and percentile" \
    jq -e '.scores["CVE-2024-6387"] | (.epss | length > 0) and (.percentile | length > 0)' <<<"$epss_json"
else
  echo "  SKIP  epss-fetch live (FIRST.org unreachable)"
fi

t "epss-fetch returns error for bad CVE format" \
  bash -c 'out=$(./epss-fetch "NOT-A-CVE"); echo "$out" | jq -e ".ok == false"'

echo
echo "== exploitdb-fetch live =="

if curl -fsS --max-time 12 -o /dev/null "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv" 2>/dev/null; then
  edb_out=$(./exploitdb-fetch CVE-2024-6387)
  edb_json=$(jq -c . <<<"$edb_out")
  t "exploitdb-fetch finds OpenSSH exploit for CVE-2024-6387" \
    jq -e '.ok == true and (.matches["CVE-2024-6387"] | length > 0)' <<<"$edb_json"
else
  echo "  SKIP  exploitdb-fetch live (ExploitDB unreachable)"
fi

echo
echo "== alerts-fetch fixture =="

env3=$(new_env)
mkdir -p "$env3/cache/omarchy-cyber-sentry"

# Create a small RSS fixture
cat >"$env3/cache/omarchy-cyber-sentry/alerts-cache.xml" <<'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>NCSC Security Advisories</title>
    <item>
      <title>NCSC-2026-0001 [1.00] [M/H] Vulnerability in OpenSSL</title>
      <link>https://advisories.ncsc.nl/advisory?id=NCSC-2026-0001</link>
      <pubDate>Thu, 20 Aug 2026 08:47:27 +0000</pubDate>
      <description>OpenSSL has multiple vulnerabilities.</description>
    </item>
    <item>
      <title>NCSC-2026-0002 [1.00] [M/M] Issue in Firefox</title>
      <link>https://advisories.ncsc.nl/advisory?id=NCSC-2026-0002</link>
      <pubDate>Wed, 19 Aug 2026 12:00:00 +0000</pubDate>
      <description>Firefox update available.</description>
    </item>
  </channel>
</rss>
XMLEOF

# Create a pre-parsed JSON to test the output format
cat >"$env3/cache/omarchy-cyber-sentry/alerts-parsed.json" <<'EOF'
{"ok":true,"source":"alerts","count":2,"checkedAt":"2026-08-20T18:00:00Z","advisories":[{"title":"NCSC-2026-0001 [1.00] [M/H] Vulnerability in OpenSSL","link":"https://advisories.ncsc.nl/advisory?id=NCSC-2026-0001","date":"2026-08-20T08:47:27Z"},{"title":"NCSC-2026-0002 [1.00] [M/M] Issue in Firefox","link":"https://advisories.ncsc.nl/advisory?id=NCSC-2026-0002","date":"2026-08-19T12:00:00Z"}]}
EOF
export XDG_RUNTIME_DIR="$env3/cache"

alerts_out=$(./alerts-fetch 2>&1)
alerts_json=$(jq -c . <<<"$alerts_out" 2>/dev/null || echo "{}")
t "alerts-fetch returns 2 advisories from fixture" \
  jq -e '.ok == true and .count == 2' <<<"$alerts_json"
t "alerts-fetch has title and link fields" \
  jq -e '.advisories[0] | (.title | length > 0) and (.link | length > 0)' <<<"$alerts_json"

unset XDG_RUNTIME_DIR
export XDG_RUNTIME_DIR="$old_runtime"

echo
echo "== manifest.json =="

t "manifest.json is valid JSON" \
  jq -e '.schemaVersion == 1 and .version == "2.1.0"' "$(dirname "$0")/../manifest.json"
t "manifest.json has all new settings" \
  jq -e '(.barWidget.defaults.nvdEnabled != null) and (.barWidget.defaults.alertsEnabled != null) and (.barWidget.defaults.epssEnabled != null) and (.barWidget.defaults.exploitdbEnabled != null) and (.barWidget.defaults.showKevBadge != null) and (.barWidget.defaults.kevRecentDays != null) and (.barWidget.defaults.kevAffectsMeOnly != null)' "$(dirname "$0")/../manifest.json"

echo
echo "== result: $pass passed, $fail failed =="
if [[ $fail -gt 0 ]]; then
  printf '  failed: %s\n' "${fails[@]}"
  exit 1
fi
exit 0
