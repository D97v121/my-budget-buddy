from collections import defaultdict
import os
from dotenv import load_dotenv

load_dotenv()  # Loads environment variables from .env
from models import Tags
def find_duplicate_tags(user_id):
    tags = Tags.query.filter_by(user_id=user_id).all()
    name_map = defaultdict(list)
    for tag in tags:
        name_map[tag.name].append(tag)

    for name, tag_list in name_map.items():
        if len(tag_list) > 1:
            print(f"Duplicate tag: {name}")
            for tag in tag_list:
                print(f" - ID: {tag.id}")