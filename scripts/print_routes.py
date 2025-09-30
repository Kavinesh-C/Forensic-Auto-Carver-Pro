import sys, os
sys.path.insert(0, r'd:\Forensic Auto Carver')
import app
for rule in app.app.url_map.iter_rules():
    print(f"{list(rule.methods)} {rule.rule} -> {rule.endpoint}")
