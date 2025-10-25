import os

# import validators.volgactf

CONFIG = {
    'DEBUG': os.getenv('DEBUG') == '1',

    'TEAMS': {
        'C4T BuT S4D': '10.80.1.2',
        'P1G SEKAI': '10.80.2.2',
        'SKSD': '10.80.3.2',
        'dtl': '10.80.4.2',
        'SPRUSH': '10.80.5.2',
        'Infobahn': '10.80.6.2',
        'thehackerscrew': '10.80.7.2',
        'BunkyoWesterns': '10.80.8.2',
        'Ganesh': '10.80.9.2',
        'SolidAll': '10.80.11.2',
        'Odin': '10.80.12.2',
        'Pinely': '10.80.13.2',
        'NPC': '10.80.14.2',
    },

    'FLAG_FORMAT' : r'[A-Z0-9]{31}=',

    'SYSTEM_PROTOCOL': 'ructf_http',
    'SYSTEM_URL': '10.80.15.2/flags',
    'SYSTEM_TOKEN': '3f397a57af3987fb', # NEED REPLACE TEAM_TOKEN

    'SUBMIT_FLAG_LIMIT': 100,
    'SUBMIT_PERIOD': 10,
    'FLAG_LIFETIME': 10 * 60,

    'SERVER_PASSWORD': os.getenv('SERVER_PASSWORD') or '@@Pwnsec',

    # For all time-related operations
    'TIMEZONE': 'Europe/Moscow',
}