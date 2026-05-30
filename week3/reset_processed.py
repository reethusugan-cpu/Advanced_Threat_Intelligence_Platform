import sys
import os

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from database.mongo_handler import collection


result = collection.update_many(

    {},

    {
        "$unset": {

            "processed": "",
            "resolved_ip": "",
            "processed_time": "",
            "blocked": ""

        }
    }
)

print(f"Reset {result.modified_count} documents")