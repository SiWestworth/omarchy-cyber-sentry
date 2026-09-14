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
# arch-fetch resolves pacman via a hardcoded absolute path (not ambient
# PATH) for security, so the PATH prepend above no longer reaches it — this
# explicit test-only seam (see _sentry-lib.sh) is what actually redirects
# it to the mock.
export SENTRY_TEST_PACMAN="$env/bin/pacman"

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

  // --- ghsaRow ---
  const ghsaWithCve = mod.ghsaRow({id:'GHSA-aaaa-bbbb-cccc',cve_id:'CVE-2026-7000',severity:'high',summary:'Bad thing',published:'2026-08-11',score:8.1,package:'lodash',ecosystem:'npm',packageCount:1,references:['https://x']});
  const ghsaWithCveType = ghsaWithCve.type;
  const ghsaWithCveSeverity = ghsaWithCve.severity;
  const ghsaWithCveCve = mod.firstCve(ghsaWithCve);
  const ghsaWithCveDesc = ghsaWithCve.description;

  const ghsaNoCve = mod.ghsaRow({id:'GHSA-dddd-eeee-ffff',cve_id:'',severity:'critical',summary:'Other thing',published:'2026-08-12',package:'foo',ecosystem:'rust',packageCount:3,references:[]});
  const ghsaNoCveCve = mod.firstCve(ghsaNoCve);
  const ghsaNoCveDesc = ghsaNoCve.description;

  // --- mergeNvdAndGhsa ---
  const mergeNvd = [mod.nvdRow({id:'CVE-2026-8000',severity:'High',score:7.0,description:'D',published:'2026-08-01'})];
  const mergeGhsaDup = mod.ghsaRow({id:'GHSA-dup',cve_id:'CVE-2026-8000',severity:'high',summary:'dup',published:'2026-08-01',package:'p',ecosystem:'npm',packageCount:1,references:[]});
  const mergeGhsaNew = mod.ghsaRow({id:'GHSA-new',cve_id:'',severity:'high',summary:'new',published:'2026-08-02',package:'q',ecosystem:'npm',packageCount:1,references:[]});
  const merged = mod.mergeNvdAndGhsa(mergeNvd, [mergeGhsaDup, mergeGhsaNew]);
  const mergedIds = merged.map(function(r){return r.id}).sort().join(',');

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

  // --- fixableSummary ---
  const fixSumRows = [fixedRow, unfixedRow, kevForFix,
    mod.archRow({name:'AVG-4',severity:'Low',packages:'baz=1.0',fixed:'2.0-1',cves:['CVE-2026-0033'],date:'2026-01-01'})];
  const fixSum = mod.fixableSummary(fixSumRows);

  // --- parsePackageList ---
  const pkgList = mod.parsePackageList('foo 1.0-1\nbar-bin 2.3.4-1\n\nbaz 5.6.7-2\n');
  const pkgNames = pkgList.map(function(p){return p.name}).join(',');
  const pkgVersions = pkgList.map(function(p){return p.version}).join(',');
  const pkgCount = pkgList.length;
  const sortedNames = mod.sortByName([{name:'zeta'},{name:'alpha'},{name:'Middle'}]).map(function(p){return p.name}).join(',');

  // --- watchlist ---
  const watchRow = mod.archRow({name:'AVG-99',severity:'Low',packages:'p',fixed:'1.0',cves:['CVE-2026-9999'],date:'2026-01-01'});
  const watchlist = ['CVE-2026-9999'];
  const isWatchedTrue = mod.isWatched(watchRow, watchlist);
  const isWatchedFalse = mod.isWatched(watchRow, []);
  const thresholdRows = [watchRow, mod.archRow({name:'AVG-98',severity:'Low',packages:'q',fixed:'1.0',cves:['CVE-2026-9998'],date:'2026-01-01'})];
  const filteredKeptIds = mod.filterByThresholdOrWatched(thresholdRows, 'High', watchlist).map(function(r){return r.id}).join(',');

  // --- dismiss ---
  const dismissRow = mod.archRow({name:'AVG-97',severity:'Critical',packages:'r',fixed:'1.0',cves:['CVE-2026-9997'],date:'2026-01-01'});
  const dismissedList = ['CVE-2026-9997'];
  const isDismissedTrue = mod.isDismissed(dismissRow, dismissedList);
  const isDismissedFalse = mod.isDismissed(dismissRow, []);
  const dismissKeptIds = mod.filterOutDismissed([dismissRow, watchRow], dismissedList).map(function(r){return r.id}).join(',');
  // Dismissal wins even over a row kept only because it's watchlisted:
  // watchRow is Low severity but survives a Critical threshold via the
  // watchlist override, then gets removed by dismissal on top of that.
  const dismissAfterWatchOverride = mod.filterOutDismissed(
    mod.filterByThresholdOrWatched([watchRow], 'Critical', watchlist),
    watchlist
  ).length === 0;

  // --- search ---
  const searchRow = mod.archRow({name:'AVG-96',severity:'High',packages:'openssl=3.0',fixed:'3.1',cves:['CVE-2026-9996'],date:'2026-01-01'});
  const searchMatchId = mod.matchesSearch(searchRow, 'AVG-96');
  const searchMatchPkg = mod.matchesSearch(searchRow, 'openssl');
  const searchMatchCase = mod.matchesSearch(searchRow, 'OPENSSL');
  const searchNoMatch = mod.matchesSearch(searchRow, 'nginx');
  const searchEmptyQueryMatches = mod.matchesSearch(searchRow, '');
  const searchAurPackage = mod.matchesSearch({name:'yay-bin', version:'12.3.5-1'}, 'yay');
  const searchFilteredIds = mod.filterBySearch([searchRow, watchRow], 'openssl').map(function(r){return r.id}).join(',');
  const searchFilteredEmptyQuery = mod.filterBySearch([searchRow, watchRow], '').length;

  // --- trend history ---
  var hist = [];
  hist = mod.appendHistoryPoint(hist, {t:'2026-01-01T00:00:00Z', badgeCount:1, kevCount:2}, 3);
  hist = mod.appendHistoryPoint(hist, {t:'2026-01-02T00:00:00Z', badgeCount:2, kevCount:3}, 3);
  hist = mod.appendHistoryPoint(hist, {t:'2026-01-03T00:00:00Z', badgeCount:3, kevCount:4}, 3);
  hist = mod.appendHistoryPoint(hist, {t:'2026-01-04T00:00:00Z', badgeCount:4, kevCount:5}, 3);
  const histLen = hist.length;
  const histFirstBadge = hist[0].badgeCount;

  const sparkFlat = mod.sparklinePoints([{badgeCount:5},{badgeCount:5}], 100, 20, 2);
  const sparkFlatYsMatch = sparkFlat.length === 2 && sparkFlat[0].y === sparkFlat[1].y;
  const sparkRange = mod.sparklinePoints([{badgeCount:0},{badgeCount:10}], 100, 20, 2);
  const sparkRangeMonotonic = sparkRange[1].x > sparkRange[0].x;
  const sparkEmptyLen = mod.sparklinePoints([], 100, 20, 2).length;

  // --- do-not-disturb ---
  const dndSameDayIn = mod.isWithinDnd('09:00', '17:00', new Date(2026,0,1,12,0));
  const dndSameDayOut = mod.isWithinDnd('09:00', '17:00', new Date(2026,0,1,20,0));
  const dndOvernightLateIn = mod.isWithinDnd('22:00', '07:00', new Date(2026,0,1,23,0));
  const dndOvernightEarlyIn = mod.isWithinDnd('22:00', '07:00', new Date(2026,0,1,3,0));
  const dndOvernightOut = mod.isWithinDnd('22:00', '07:00', new Date(2026,0,1,12,0));
  const dndBadInput = mod.isWithinDnd('bad', '07:00', new Date(2026,0,1,23,0));

  // --- osvRow ---
  const osv = mod.osvRow({id:'GHSA-xxxx',ecosystem:'npm',package:'lodash',version:'4.17.15',summary:'ReDoS',severity:'MEDIUM',references:['https://x'],aliases:['CVE-2020-28500']});
  const osvType = osv.type;
  const osvCve = mod.firstCve(osv);
  const osvNoAliasRow = mod.osvRow({id:'GHSA-yyyy',ecosystem:'PyPI',package:'foo',version:'1.0',summary:'S',severity:'HIGH',references:[],aliases:[]});
  const osvNoAliasCve = mod.firstCve(osvNoAliasRow);

  // --- Array.isArray regression: rows read back through a QML ListView's
  // modelData marshal nested arrays into an array-like (has .length, is
  // indexable) that is NOT a real JS Array — Array.isArray() on it is
  // false. firstCve()/hasExploit() must still work via duck-typing.
  // `arguments` is a real-world example of exactly this kind of object.
  const arrayLike = (function() { return arguments; })('CVE-2026-4242');
  const isArrayLikeRealArray = Array.isArray(arrayLike);
  const duckTypedCve = mod.firstCve({cves: arrayLike});
  const duckTypedExploit = mod.hasExploit({exploitTitles: (function() { return arguments; })('t1')});

  // --- buildRows with 6 sources ---
  const allRows = mod.buildRows(
    {advisories:[{name:'A1',severity:'High',packages:'p',fixed:'1.0',issues:['CVE-1'],date:'2026-01-01'}]},
    {vulnerabilities:[{cveID:'CVE-2',vendorProject:'X',product:'Y',vulnerabilityName:'Z',dateAdded:'2026-08-01'}]},
    {cves:[{id:'CVE-3',severity:'High',score:7.5,description:'D',published:'2026-08-10'}]},
    {advisories:[{title:'Alert 1',link:'https://l',date:'2026-08-12'}]},
    {findings:[{id:'GHSA-zzzz',ecosystem:'npm',package:'p',version:'1.0',summary:'s',severity:'HIGH',references:[],aliases:[]}]},
    {advisories:[{id:'GHSA-yyyy',cve_id:'',severity:'high',summary:'s2',published:'2026-08-13',package:'q',ecosystem:'npm',packageCount:1,references:[]}]}
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
    sortedNames: sortedNames,
    ghsaWithCveType: ghsaWithCveType, ghsaWithCveSeverity: ghsaWithCveSeverity,
    ghsaWithCveCve: ghsaWithCveCve, ghsaWithCveDesc: ghsaWithCveDesc,
    ghsaNoCveCve: ghsaNoCveCve, ghsaNoCveDesc: ghsaNoCveDesc,
    mergedIds: mergedIds,
    searchMatchId: searchMatchId, searchMatchPkg: searchMatchPkg, searchMatchCase: searchMatchCase,
    searchNoMatch: searchNoMatch, searchEmptyQueryMatches: searchEmptyQueryMatches,
    searchAurPackage: searchAurPackage, searchFilteredIds: searchFilteredIds,
    searchFilteredEmptyQuery: searchFilteredEmptyQuery,
    isWatchedTrue: isWatchedTrue, isWatchedFalse: isWatchedFalse,
    isDismissedTrue: isDismissedTrue, isDismissedFalse: isDismissedFalse,
    dismissKeptIds: dismissKeptIds, dismissAfterWatchOverride: dismissAfterWatchOverride,
    filteredKeptIds: filteredKeptIds,
    histLen: histLen, histFirstBadge: histFirstBadge,
    sparkFlatYsMatch: sparkFlatYsMatch, sparkRangeMonotonic: sparkRangeMonotonic, sparkEmptyLen: sparkEmptyLen,
    dndSameDayIn: dndSameDayIn, dndSameDayOut: dndSameDayOut,
    dndOvernightLateIn: dndOvernightLateIn, dndOvernightEarlyIn: dndOvernightEarlyIn, dndOvernightOut: dndOvernightOut,
    dndBadInput: dndBadInput,
    osvType: osvType, osvCve: osvCve, osvNoAliasCve: osvNoAliasCve,
    isArrayLikeRealArray: isArrayLikeRealArray, duckTypedCve: duckTypedCve, duckTypedExploit: duckTypedExploit,
    fixSumFixable: fixSum.fixable, fixSumTotal: fixSum.total
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
  t "SentryModel.ghsaRow: type is ghsa" \
    jq -e '.ghsaWithCveType == "ghsa"' <<<"$model_test"
  t "SentryModel.ghsaRow: severity uppercased" \
    jq -e '.ghsaWithCveSeverity == "HIGH"' <<<"$model_test"
  t "SentryModel.ghsaRow: firstCve picks up cve_id when present" \
    jq -e '.ghsaWithCveCve == "CVE-2026-7000"' <<<"$model_test"
  t "SentryModel.ghsaRow: description carries an ecosystem/package tag" \
    jq -e '.ghsaWithCveDesc | contains("[npm · lodash]")' <<<"$model_test"
  t "SentryModel.ghsaRow: firstCve empty when cve_id is blank" \
    jq -e '.ghsaNoCveCve == ""' <<<"$model_test"
  t "SentryModel.ghsaRow: '\''+N more'\'' suffix for multi-package advisories" \
    jq -e '.ghsaNoCveDesc | contains("+2 more")' <<<"$model_test"
  t "SentryModel.mergeNvdAndGhsa: drops a GHSA entry duplicating an NVD CVE" \
    jq -e '.mergedIds == "CVE-2026-8000,GHSA-new"' <<<"$model_test"
  t "SentryModel.matchesSearch: matches on id" \
    jq -e '.searchMatchId == true' <<<"$model_test"
  t "SentryModel.matchesSearch: matches on packages" \
    jq -e '.searchMatchPkg == true' <<<"$model_test"
  t "SentryModel.matchesSearch: case-insensitive" \
    jq -e '.searchMatchCase == true' <<<"$model_test"
  t "SentryModel.matchesSearch: false when nothing matches" \
    jq -e '.searchNoMatch == false' <<<"$model_test"
  t "SentryModel.matchesSearch: empty query always matches" \
    jq -e '.searchEmptyQueryMatches == true' <<<"$model_test"
  t "SentryModel.matchesSearch: works on plain AUR {name,version} objects" \
    jq -e '.searchAurPackage == true' <<<"$model_test"
  t "SentryModel.filterBySearch: keeps only the matching row" \
    jq -e '.searchFilteredIds == "AVG-96"' <<<"$model_test"
  t "SentryModel.filterBySearch: empty query keeps everything" \
    jq -e '.searchFilteredEmptyQuery == 2' <<<"$model_test"
  t "SentryModel.alertRow: type is alert" \
    jq -e '.alertType == "alert"' <<<"$model_test"
  t "SentryModel.buildRows: 6 source types" \
    jq -e '.rowTypes == "alert,arch,ghsa,kev,nvd,osv"' <<<"$model_test"
  t "SentryModel.osvRow: type is osv" \
    jq -e '.osvType == "osv"' <<<"$model_test"
  t "SentryModel.osvRow: firstCve picks up a CVE alias when present" \
    jq -e '.osvCve == "CVE-2020-28500"' <<<"$model_test"
  t "SentryModel.osvRow: firstCve is empty when there is no CVE alias" \
    jq -e '.osvNoAliasCve == ""' <<<"$model_test"
  t "regression: 'arguments' is array-like but not Array.isArray" \
    jq -e '.isArrayLikeRealArray == false' <<<"$model_test"
  t "regression: firstCve works on a non-Array.isArray array-like (ListView modelData shape)" \
    jq -e '.duckTypedCve == "CVE-2026-4242"' <<<"$model_test"
  t "regression: hasExploit works on a non-Array.isArray array-like" \
    jq -e '.duckTypedExploit == true' <<<"$model_test"
  t "SentryModel.archFixState: command is always full-system update" \
    jq -e '.fixCommand == "sudo pacman -Syu"' <<<"$model_test"
  t "SentryModel.archFixState: packages passed through unmodified" \
    jq -e '.fixPackages == "foo=1.0;bar=2.0"' <<<"$model_test"
  t "SentryModel.archFixState: version passed through unmodified" \
    jq -e '.fixVersion == "3.0-1"' <<<"$model_test"
  t "SentryModel.archFixState: null when advisory has no fix released" \
    jq -e '.noFixState == null' <<<"$model_test"
  t "SentryModel.fixableSummary: counts only fixed, non-unfixed arch rows" \
    jq -e '.fixSumFixable == 2' <<<"$model_test"
  t "SentryModel.fixableSummary: total excludes non-arch rows" \
    jq -e '.fixSumTotal == 3' <<<"$model_test"
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
  t "SentryModel.isWatched: true when CVE is in the watchlist" \
    jq -e '.isWatchedTrue == true' <<<"$model_test"
  t "SentryModel.isWatched: false for an empty watchlist" \
    jq -e '.isWatchedFalse == false' <<<"$model_test"
  t "SentryModel.isDismissed: true when CVE is in the dismissed list" \
    jq -e '.isDismissedTrue == true' <<<"$model_test"
  t "SentryModel.isDismissed: false for an empty dismissed list" \
    jq -e '.isDismissedFalse == false' <<<"$model_test"
  t "SentryModel.filterOutDismissed: drops the dismissed row, keeps the other" \
    jq -e '.dismissKeptIds == "AVG-99"' <<<"$model_test"
  t "SentryModel.filterOutDismissed: dismissal overrides a watchlist-kept row" \
    jq -e '.dismissAfterWatchOverride == true' <<<"$model_test"
  t "SentryModel.filterByThresholdOrWatched: keeps a watched row below threshold" \
    jq -e '.filteredKeptIds == "AVG-99"' <<<"$model_test"
  t "SentryModel.appendHistoryPoint: caps length at maxPoints" \
    jq -e '.histLen == 3' <<<"$model_test"
  t "SentryModel.appendHistoryPoint: drops oldest point first" \
    jq -e '.histFirstBadge == 2' <<<"$model_test"
  t "SentryModel.sparklinePoints: flat series renders equal y values" \
    jq -e '.sparkFlatYsMatch == true' <<<"$model_test"
  t "SentryModel.sparklinePoints: x increases across points" \
    jq -e '.sparkRangeMonotonic == true' <<<"$model_test"
  t "SentryModel.sparklinePoints: empty history yields no points" \
    jq -e '.sparkEmptyLen == 0' <<<"$model_test"
  t "SentryModel.isWithinDnd: same-day window matches inside" \
    jq -e '.dndSameDayIn == true' <<<"$model_test"
  t "SentryModel.isWithinDnd: same-day window excludes outside" \
    jq -e '.dndSameDayOut == false' <<<"$model_test"
  t "SentryModel.isWithinDnd: overnight window matches late evening" \
    jq -e '.dndOvernightLateIn == true' <<<"$model_test"
  t "SentryModel.isWithinDnd: overnight window matches early morning" \
    jq -e '.dndOvernightEarlyIn == true' <<<"$model_test"
  t "SentryModel.isWithinDnd: overnight window excludes midday" \
    jq -e '.dndOvernightOut == false' <<<"$model_test"
  t "SentryModel.isWithinDnd: malformed time input fails open (false)" \
    jq -e '.dndBadInput == false' <<<"$model_test"
else
  echo "  SKIP  SentryModel.js (node unavailable)"
fi

unset XDG_RUNTIME_DIR PATH FAKE_INSTALLED SENTRY_TEST_PACMAN
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
echo "== osv-fetch =="

env4=$(new_env)
mkdir -p "$env4/bin" "$env4/cache/omarchy-cyber-sentry"

cat >"$env4/bin/fake-npm" <<'EOF'
#!/bin/bash
echo '{"dependencies":{"lodash":{"version":"4.17.15"}}}'
EOF
chmod +x "$env4/bin/fake-npm"

export XDG_RUNTIME_DIR="$env4/cache"
export SENTRY_TEST_NPM="$env4/bin/fake-npm"
export SENTRY_TEST_PIP=/nonexistent
export SENTRY_TEST_CARGO=/nonexistent
export SENTRY_TEST_GO=/nonexistent

osv_out=$(./osv-fetch --force 2>&1)
osv_json=$(jq -c . <<<"$osv_out" 2>/dev/null || echo "{}")

t "osv-fetch scans exactly the one fake-npm global package" \
  jq -e '.scanned == 1' <<<"$osv_json"
t "osv-fetch finds real OSV vulnerabilities for lodash 4.17.15" \
  jq -e '.ok == true and (.count > 0)' <<<"$osv_json"
t "osv-fetch finding carries ecosystem, package, version, severity" \
  jq -e '.findings[0] | (.ecosystem == "npm") and (.package == "lodash") and (.version == "4.17.15") and (.severity | length > 0)' <<<"$osv_json"
t "osv-fetch normalizes OSV's MODERATE severity to MEDIUM" \
  jq -e '[.findings[] | select(.id == "GHSA-29mw-wpgm-hmr9")][0].severity == "MEDIUM"' <<<"$osv_json"
t "osv-fetch surfaces the CVE alias for watchlist/EPSS enrichment" \
  jq -e '[.findings[] | select(.id == "GHSA-29mw-wpgm-hmr9")][0].aliases | index("CVE-2020-28500") != null' <<<"$osv_json"

# All four ecosystem tools absent: not an error, just nothing scanned.
env5=$(new_env)
mkdir -p "$env5/cache/omarchy-cyber-sentry"
export XDG_RUNTIME_DIR="$env5/cache"
export SENTRY_TEST_NPM=/nonexistent
export SENTRY_TEST_PIP=/nonexistent
export SENTRY_TEST_CARGO=/nonexistent
export SENTRY_TEST_GO=/nonexistent

osv_empty_out=$(./osv-fetch --force 2>&1)
osv_empty_json=$(jq -c . <<<"$osv_empty_out" 2>/dev/null || echo "{}")
t "osv-fetch with no ecosystem tools present is ok:true with 0 scanned, not an error" \
  jq -e '.ok == true and .scanned == 0 and .count == 0' <<<"$osv_empty_json"

unset SENTRY_TEST_NPM SENTRY_TEST_PIP SENTRY_TEST_CARGO SENTRY_TEST_GO
export XDG_RUNTIME_DIR="$old_runtime"

echo
echo "== ghsa-fetch live =="

env6=$(new_env)
mkdir -p "$env6/cache/omarchy-cyber-sentry"
export XDG_RUNTIME_DIR="$env6/cache"

ghsa_out=$(./ghsa-fetch --force 2>&1)
ghsa_json=$(jq -c . <<<"$ghsa_out" 2>/dev/null || echo "{}")

t "ghsa-fetch returns ok:true with a non-trivial count" \
  jq -e '.ok == true and (.count > 50)' <<<"$ghsa_json"
t "ghsa-fetch advisories are deduplicated by id" \
  jq -e '(.advisories | length) == (.advisories | map(.id) | unique | length)' <<<"$ghsa_json"
t "ghsa-fetch advisory carries id, severity, summary, and published date" \
  jq -e '.advisories[0] | (.id | startswith("GHSA-")) and (.severity | length > 0) and (.summary | length > 0) and (.published | length > 0)' <<<"$ghsa_json"
t "ghsa-fetch includes at least one advisory with no CVE assigned" \
  jq -e '[.advisories[] | select(.cve_id == "")] | length > 0' <<<"$ghsa_json"
t "ghsa-fetch severity values are only high or critical" \
  jq -e '[.advisories[].severity] | unique | (. - ["high","critical"]) | length == 0' <<<"$ghsa_json"

export XDG_RUNTIME_DIR="$old_runtime"

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
  jq -e '.schemaVersion == 1 and .version == "2.4.0"' "$(dirname "$0")/../manifest.json"
t "manifest.json has all new settings" \
  jq -e '(.barWidget.defaults.nvdEnabled != null) and (.barWidget.defaults.alertsEnabled != null) and (.barWidget.defaults.epssEnabled != null) and (.barWidget.defaults.exploitdbEnabled != null) and (.barWidget.defaults.showKevBadge != null) and (.barWidget.defaults.kevRecentDays != null) and (.barWidget.defaults.kevAffectsMeOnly != null) and (.barWidget.defaults.osvEnabled != null) and (.barWidget.defaults.ghsaEnabled != null)' "$(dirname "$0")/../manifest.json"
t "manifest.json has the trend/watchlist/digest/dnd settings" \
  jq -e '(.barWidget.defaults.showTrend != null) and (.barWidget.defaults.digestEnabled != null) and (.barWidget.defaults.digestIntervalDays != null) and (.barWidget.defaults.dndEnabled != null) and (.barWidget.defaults.dndStart != null) and (.barWidget.defaults.dndEnd != null)' "$(dirname "$0")/../manifest.json"
t "manifest.json schema keys match defaults keys exactly" \
  jq -e '(.barWidget.defaults | keys | sort) == (.barWidget.schema | map(.key) | sort)' "$(dirname "$0")/../manifest.json"

echo
echo "== result: $pass passed, $fail failed =="
if [[ $fail -gt 0 ]]; then
  printf '  failed: %s\n' "${fails[@]}"
  exit 1
fi
exit 0
