# verify_json.py
import json

with open('data/campus_entities.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

skip_keys = [
    'scam_fee_keywords',
    'scam_urgency_keywords', 
    'scam_contact_keywords',
    'legitimate_process_keywords'
]

categories = list(data.keys())
print('Categories found:', len(categories))

total_entities = 0
for cat, entities in data.items():
    if cat not in skip_keys:
        count = len(entities)
        total_entities += count
        print(f'  {cat}: {count} entities')

print(f'Total entities: {total_entities}')
print(f'Scam fee keywords: {len(data["scam_fee_keywords"])}')
print(f'Urgency keywords: {len(data["scam_urgency_keywords"])}')
print('JSON loaded correctly')