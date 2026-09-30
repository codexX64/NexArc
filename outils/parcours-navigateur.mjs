// Parcours réel de Sentinel dans Chromium (clé d'accès virtuelle) et contrôle de
// mise en page à chaque largeur. Usage :
//   node outils/parcours-navigateur.mjs http://localhost:8090 JETON DOSSIER
import { chromium } from 'playwright';
import fs from 'node:fs';
import { chevauchements, LARGEURS } from '../socle/essai/mise-en-page.mjs';

const [base, jeton, sortie = '/tmp/captures-sentinel'] = process.argv.slice(2);
fs.mkdirSync(sortie, { recursive: true });
const MDP = 'phrase de passe pour sentinel en local';
const navigateur = await chromium.launch();
const contexte = await navigateur.newContext({ viewport: { width: 1280, height: 860 } });
const page = await contexte.newPage();
contexte.setDefaultTimeout(12000);
const erreurs = [];
page.on('console', m => { if (m.type() === 'error') erreurs.push(m.text()); });
page.on('pageerror', e => erreurs.push(String(e)));
const cdp = await contexte.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

const rapport = [];
async function controle(nom) {
  for (const w of LARGEURS) {
    await page.setViewportSize({ width: w, height: w < 500 ? 780 : 900 });
    await page.waitForTimeout(220);
    const defauts = await page.evaluate(chevauchements);
    // Une valeur absente rendue telle quelle (« null », « undefined », « NaN ») est un défaut d'affichage.
    const brut = await page.evaluate(() => (document.body.innerText.match(/\b(null|undefined|NaN)\b/) || [])[0]);
    if (brut) defauts.push({ type: 'texte-brut', detail: `« ${brut} » affiché` });
    rapport.push({ ecran: nom, largeur: w, defauts });
    if ([360, 768, 1280].includes(w)) await page.screenshot({ path: `${sortie}/${nom}-${w}.png` });
  }
  await page.setViewportSize({ width: 1280, height: 860 });
}

await page.goto(base);
await page.getByLabel('Jeton d’installation').fill(jeton);
await page.getByLabel('Identifiant').fill('ana');
await page.getByLabel('Mot de passe').fill(MDP);
await page.getByRole('button', { name: 'Créer le compte' }).click();
await page.getByRole('button', { name: /Créer la clé maintenant/ }).click();
await page.getByText('J’ai rangé ces codes en lieu sûr.').click();
await page.getByRole('button', { name: 'Terminer' }).click();
await page.locator('.app').waitFor();
await page.getByRole('heading', { name: 'Tableau de bord' }).waitFor();
await controle('tableau');

// Seed d'une machine par l'API (session du navigateur), puis rechargement pour
// que le parc apparaisse : on exerce ainsi la fiche, les composants, les tâches.
// Antivirus inactif : la page Alertes montre une alerte ouverte, pas une liste vide.
await page.evaluate(async () => {
  const info = await (await fetch('/api/enroll/info?site=Prod', { credentials: 'same-origin' })).json();
  const conf = await (await fetch('/api/enroll/config?code=' + info.code)).json();
  await fetch('/api/ingest', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Agent-Token': conf.token }, body: JSON.stringify({ hostname: 'serveur-a', ip: '198.51.100.12', os: 'Ubuntu 24.04 LTS', oskind: 'lin', cpu: 22, ram: 48, disk: 61, av: 'inactif', fw: 'actif', enc: 'LUKS actif', patch: 2, inventory: { hostname: 'serveur-a', cpu_model: 'CPU', cpu_cores: 4, cpu_threads: 8, ram_total_gb: 16, disks: [{ device: '/dev/sda', mount: '/', fs: 'ext4', total_gb: 240, used_pct: 61 }], nics: [{ name: 'eth0', ip: '198.51.100.12', mac: '01:23:45:67:89:ab' }] } }) });
});
await page.reload();
await page.locator('.app').waitFor();
await page.getByRole('heading', { name: 'Tableau de bord' }).waitFor();

for (const [bouton, titre, nom] of [['Postes', 'Postes', 'postes'], ['Alertes', 'Alertes', 'alertes'], ['Correctifs', 'Correctifs', 'correctifs'], ['Automatisations', 'Automatisations', 'automatisations'], ['Réglages', 'Réglages', 'reglages'], ['Sécurité', 'Sécurité', 'securite'], ['Comptes', 'Comptes', 'comptes']]) {
  await page.locator('.rail').getByRole('button', { name: bouton, exact: true }).click();
  await page.getByRole('heading', { name: titre, exact: true }).first().waitFor();
  await page.waitForTimeout(300);
  await controle(nom);
  if (nom === 'alertes') await page.getByText('Antivirus inactif.').first().waitFor();
  if (nom === 'postes') {
    await page.locator('tbody tr', { hasText: 'serveur-a' }).first().click();
    await page.getByRole('heading', { name: 'serveur-a' }).waitFor();
    await controle('fiche');
    await page.getByRole('button', { name: 'Composants' }).click();
    await page.waitForTimeout(200);
    await controle('fiche-composants');
    // Gestionnaire d'accès, avec le bloc Redfish (administrateur).
    await page.getByRole('button', { name: 'Accès distants' }).click();
    await page.getByRole('dialog').getByText('Contrôle d\'alimentation (Redfish)').waitFor();
    await controle('acces-distants');
    await page.getByRole('dialog').getByRole('button', { name: 'Fermer' }).click();
  }
}

// Dialogue d'inscription (génère un code) et gestionnaire d'accès.
await page.locator('.rail').getByRole('button', { name: 'Postes', exact: true }).click();
await page.getByRole('button', { name: 'Ajouter un poste' }).first().click();
await page.getByRole('dialog').waitFor();
await page.waitForTimeout(400);
await controle('inscription');
await page.getByRole('dialog').getByRole('button', { name: 'Fermer' }).click();

const defauts = rapport.filter(r => r.defauts.length);
fs.writeFileSync(`${sortie}/rapport.json`, JSON.stringify({ rapport, erreurs }, null, 2));
console.log(`écrans×largeurs contrôlés : ${rapport.length}, avec défauts : ${defauts.length}, erreurs console : ${erreurs.length}`);
for (const r of defauts) for (const d of r.defauts.slice(0, 6)) console.log(`  ${r.ecran} @${r.largeur} — ${d.type} : ${d.detail}`);
for (const e of erreurs) console.log('  console :', e);
await navigateur.close();
process.exit(defauts.length || erreurs.length ? 1 : 0);
