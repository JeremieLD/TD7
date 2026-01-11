# %% [markdown]
# # Projet : Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE
# 
# **Objectifs :**
# 1. Extraire les bulletins ANSSI (avis et alertes)
# 2. Identifier les CVE mentionnées
# 3. Enrichir avec API MITRE et EPSS
# 4. Consolider dans un DataFrame
# 5. Analyser et visualiser
# 6. Générer des alertes

# %% [markdown]
# ## 📦 IMPORTS ET CONFIGURATION

# %%
# Imports
import feedparser
import requests
import re
import json
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Configuration graphiques
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")
plt.rcParams['figure.figsize'] = (12, 6)

print("✅ Imports OK")

# %%
# ============================================================================
# CONFIGURATION
# ============================================================================

USE_LOCAL_DATA = True  # True = données locales, False = API

# Chemins
DATA_DIR = Path("data_pour_TD_final_2026")
ALERTES_DIR = DATA_DIR / "alertes"
AVIS_DIR = DATA_DIR / "avis"
FIRST_DIR = DATA_DIR / "first"
MITRE_DIR = DATA_DIR / "mitre"
OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

# URLs
URL_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed"
URL_ALERTE = "https://www.cert.ssi.gouv.fr/alerte/feed"

# Rate limiting
RATE_LIMIT_DELAY = 2

# Pattern CVE
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"

print(f"🔧 Mode: {'LOCAL' if USE_LOCAL_DATA else 'EN LIGNE'}")

# %%
# Fonction utilitaire
def get_severity(score):
    """Retourne la sévérité selon le score CVSS"""
    if score == "Non renseigné" or score is None:
        return "Non renseigné"
    try:
        score = float(score)
        if score >= 9.0:
            return "Critique"
        elif score >= 7.0:
            return "Elevée"
        elif score >= 4.0:
            return "Moyenne"
        else:
            return "Faible"
    except:
        return "Non renseigné"

# %% [markdown]
# ## 1️⃣ EXTRACTION DES BULLETINS

# %%
def charger_bulletins_local():
    """Charge bulletins depuis fichiers JSON locaux"""
    bulletins = []
    
    print("📡 Chargement local...")
    
    # Alertes
    if ALERTES_DIR.exists():
        for file in ALERTES_DIR.glob("*.json"):
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    cves = list(set(re.findall(CVE_PATTERN, str(data))))
                    bulletins.append({
                        "titre": data.get("title", "Sans titre"),
                        "type": "Alerte",
                        "date": data.get("published", "Date inconnue"),
                        "lien": data.get("link", ""),
                        "cves": cves
                    })
            except Exception as e:
                print(f"⚠️ {file.name}: {e}")
    
    # Avis
    if AVIS_DIR.exists():
        for file in AVIS_DIR.glob("*.json"):
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    cves = list(set(re.findall(CVE_PATTERN, str(data))))
                    bulletins.append({
                        "titre": data.get("title", "Sans titre"),
                        "type": "Avis",
                        "date": data.get("published", "Date inconnue"),
                        "lien": data.get("link", ""),
                        "cves": cves
                    })
            except Exception as e:
                print(f"⚠️ {file.name}: {e}")
    
    print(f"✅ {len(bulletins)} bulletins")
    return bulletins

def charger_bulletins_online():
    """Charge bulletins depuis flux RSS"""
    bulletins = []
    
    print("📡 Chargement RSS...")
    
    # Avis
    feed = feedparser.parse(URL_AVIS)
    for entry in feed.entries:
        bulletins.append({
            "titre": entry.title,
            "type": "Avis",
            "date": entry.published,
            "lien": entry.link,
            "cves": []
        })
    time.sleep(RATE_LIMIT_DELAY)
    
    # Alertes
    feed = feedparser.parse(URL_ALERTE)
    for entry in feed.entries:
        bulletins.append({
            "titre": entry.title,
            "type": "Alerte",
            "date": entry.published,
            "lien": entry.link,
            "cves": []
        })
    
    print(f"✅ {len(bulletins)} bulletins")
    return bulletins

# %%
# Chargement
if USE_LOCAL_DATA:
    bulletins = charger_bulletins_local()
else:
    bulletins = charger_bulletins_online()

# Aperçu
print(f"\n📋 Aperçu (5 premiers):")
for i, b in enumerate(bulletins[:5], 1):
    print(f"{i}. [{b['type']}] {b['titre'][:60]}... ({len(b['cves'])} CVE)")

# %% [markdown]
# ## 2️⃣ EXTRACTION CVE (si mode online)

# %%
def extraire_cves_online(lien):
    """Extrait CVE d'un bulletin en ligne"""
    try:
        url = lien.rstrip('/') + '/json/'
        time.sleep(RATE_LIMIT_DELAY)
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return list(set(re.findall(CVE_PATTERN, str(data))))
    except Exception as e:
        print(f"⚠️ {e}")
        return []

# %%
# Si online, extraire CVE
if not USE_LOCAL_DATA:
    print("🔍 Extraction CVE...")
    for i, b in enumerate(bulletins, 1):
        print(f"[{i}/{len(bulletins)}]", end=" ")
        b['cves'] = extraire_cves_online(b['lien'])
        print(f"✓ ({len(b['cves'])})")

# %%
# Stats CVE
total_cves = sum(len(b['cves']) for b in bulletins)
uniques = len(set(cve for b in bulletins for cve in b['cves']))

print(f"\n📊 STATS CVE")
print(f"Total (doublons)  : {total_cves}")
print(f"CVE uniques       : {uniques}")
print(f"Moyenne/bulletin  : {total_cves / len(bulletins):.1f}")

# %% [markdown]
# ## 3️⃣ ENRICHISSEMENT DES CVE

# %%
# Fonctions MITRE
def charger_mitre_local(cve_id):
    """Charge CVE MITRE local"""
    path = MITRE_DIR / f"{cve_id}.json"
    if not path.exists():
        path = MITRE_DIR / cve_id
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return None

def charger_mitre_online(cve_id):
    """Charge CVE MITRE API"""
    try:
        time.sleep(RATE_LIMIT_DELAY)
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except:
        return None

def extraire_mitre(cve_id, data):
    """Extrait données MITRE"""
    if not data:
        return {
            "description": "Non renseigné",
            "cvss_score": "Non renseigné",
            "base_severity": "Non renseigné",
            "cwe_id": "Non disponible",
            "cwe_desc": "Non disponible",
            "vendor": "Non renseigné",
            "product": "Non renseigné",
            "versions": "Non renseigné"
        }
    
    try:
        cna = data.get("containers", {}).get("cna", {})
        
        # Description
        desc_list = cna.get("descriptions", [])
        description = desc_list[0].get("value", "Non renseigné") if desc_list else "Non renseigné"
        
        # CVSS
        cvss = "Non renseigné"
        metrics = cna.get("metrics", [])
        if metrics:
            m = metrics[0]
            for v in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if v in m:
                    cvss = m[v].get("baseScore", "Non renseigné")
                    break
        
        # CWE
        cwe_id = "Non disponible"
        cwe_desc = "Non disponible"
        prob = cna.get("problemTypes", [])
        if prob and "descriptions" in prob[0]:
            d = prob[0]["descriptions"][0]
            cwe_id = d.get("cweId", "Non disponible")
            cwe_desc = d.get("description", "Non disponible")
        
        # Produits
        vendor = "Non renseigné"
        product = "Non renseigné"
        versions = "Non renseigné"
        aff = cna.get("affected", [])
        if aff:
            vendor = aff[0].get("vendor", "Non renseigné")
            product = aff[0].get("product", "Non renseigné")
            v_list = [v.get("version") for v in aff[0].get("versions", []) 
                     if v.get("status") == "affected"]
            versions = ", ".join(v_list) if v_list else "Non renseigné"
        
        return {
            "description": description,
            "cvss_score": cvss,
            "base_severity": get_severity(cvss),
            "cwe_id": cwe_id,
            "cwe_desc": cwe_desc,
            "vendor": vendor,
            "product": product,
            "versions": versions
        }
    except:
        return {
            "description": "Non renseigné",
            "cvss_score": "Non renseigné",
            "base_severity": "Non renseigné",
            "cwe_id": "Non disponible",
            "cwe_desc": "Non disponible",
            "vendor": "Non renseigné",
            "product": "Non renseigné",
            "versions": "Non renseigné"
        }

# %%
# Fonctions EPSS
def charger_epss_local(cve_id):
    """Charge EPSS local"""
    path = FIRST_DIR / cve_id
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            epss_data = data.get("data", [])
            if epss_data:
                return epss_data[0].get("epss", "Non renseigné")
    except:
        pass
    return "Non renseigné"

def charger_epss_online(cve_id):
    """Charge EPSS API"""
    try:
        time.sleep(RATE_LIMIT_DELAY)
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        epss = data.get("data", [])
        if epss:
            return epss[0].get("epss", "Non renseigné")
    except:
        pass
    return "Non renseigné"

# %%
# Enrichissement
print("🔍 ENRICHISSEMENT")
print("=" * 80)

tous_cves = list(set(cve for b in bulletins for cve in b['cves']))
print(f"CVE uniques à enrichir : {len(tous_cves)}")

cve_dict = {}

for i, cve_id in enumerate(tous_cves, 1):
    print(f"[{i}/{len(tous_cves)}] {cve_id}...", end=" ")
    
    # MITRE
    if USE_LOCAL_DATA:
        mitre_raw = charger_mitre_local(cve_id)
    else:
        mitre_raw = charger_mitre_online(cve_id)
    
    mitre = extraire_mitre(cve_id, mitre_raw)
    
    # EPSS
    if USE_LOCAL_DATA:
        epss = charger_epss_local(cve_id)
    else:
        epss = charger_epss_online(cve_id)
    
    cve_dict[cve_id] = {
        "cve_id": cve_id,
        "epss_score": epss,
        **mitre
    }
    
    print("✓")

print(f"\n✅ {len(cve_dict)} CVE enrichis")

# %%
# Aperçu enrichissement
print("\n📋 APERÇU (3 premiers):")
for cve in list(cve_dict.values())[:3]:
    print(f"\n🔹 {cve['cve_id']}")
    print(f"   CVSS  : {cve['cvss_score']} ({cve['base_severity']})")
    print(f"   EPSS  : {cve['epss_score']}")
    print(f"   CWE   : {cve['cwe_id']}")
    print(f"   Produit: {cve['product']}")

# %% [markdown]
# ## 4️⃣ CONSOLIDATION DATAFRAME

# %%
print("📋 CONSTRUCTION DATAFRAME")

lignes = []

for bulletin in bulletins:
    for cve_id in bulletin["cves"]:
        cve_data = cve_dict.get(cve_id, {})
        
        ligne = {
            "Titre du bulletin (ANSSI)": bulletin["titre"],
            "Type de bulletin": bulletin["type"],
            "Date de publication": bulletin["date"],
            "Identifiant CVE": cve_id,
            "Score CVSS": cve_data.get("cvss_score", "Non renseigné"),
            "Base Severity": cve_data.get("base_severity", "Non renseigné"),
            "Type CWE": cve_data.get("cwe_id", "Non disponible"),
            "CWE Description": cve_data.get("cwe_desc", "Non disponible"),
            "Score EPSS": cve_data.get("epss_score", "Non renseigné"),
            "Lien du bulletin (ANSSI)": bulletin["lien"],
            "Description": cve_data.get("description", "Non renseigné"),
            "Editeur/Vendor": cve_data.get("vendor", "Non renseigné"),
            "Produit": cve_data.get("product", "Non renseigné"),
            "Versions affectées": cve_data.get("versions", "Non renseigné")
        }
        
        lignes.append(ligne)

df_final = pd.DataFrame(lignes)

print(f"✅ {len(df_final)} lignes × {len(df_final.columns)} colonnes")

# %%
# Nettoyage
df_final['Score CVSS'] = pd.to_numeric(df_final['Score CVSS'], errors='coerce')
df_final['Score EPSS'] = pd.to_numeric(df_final['Score EPSS'], errors='coerce')
df_final['Date de publication'] = pd.to_datetime(df_final['Date de publication'], errors='coerce')
df_final['Année'] = df_final['Date de publication'].dt.year
df_final['Mois'] = df_final['Date de publication'].dt.month
df_final['Année-Mois'] = df_final['Date de publication'].dt.to_period('M')

print("✅ Nettoyage OK")

# %%
# Aperçu
df_final.head(10)

# %%
# Export CSV
output_file = OUTPUT_DIR / "tableau_final.csv"
df_final.to_csv(output_file, index=False, encoding="utf-8")
print(f"💾 Sauvegardé : {output_file}")

# %%
# Stats descriptives
df_final.describe(include='all')