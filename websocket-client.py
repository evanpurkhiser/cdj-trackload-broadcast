#!/usr/bin/env python3

import sys
import asyncio
import websockets
import mutagen
import json
import base64
import os

MUSIC_PATH = '/home/evan/documents/multimedia/djing/tracks'

def get_track_details(load_line):
  deck_id, path = load_line.split(':', 1)
  full_path = os.path.join(MUSIC_PATH, path)

  track = mutagen.File(full_path).tags

  art = track.getall('APIC')

  # Convert the artwork into base 64
  if len(art) > 0:
    data = base64.b64encode(art[0].data).decode('utf-8')
    mime = art[0].mime

    artwork = 'data:{mime};base64,{data}'.format(mime=mime, data=data)

  return {
      'deck_id': deck_id,
      'artist':  track['TPE1'].text[0],
      'title':   track['TIT2'].text[0],
      'album':   track['TALB'].text[0] if 'TALB' in track else None,
      'key':     track['TKEY'].text[0] if 'TKEY' in track else None,
      'label':   track['TPUB'].text[0] if 'TPUB' in track else None,
      'release': track['COMM::XXX'].text[0] if 'COMM::XXX' in track else None,
      'year':    track['TDRC'].text[0].get_text() if 'TDRC' in track else None,
      'artwork': artwork,
  }

async def time(websocket, path):
  reader, writer = await asyncio.open_connection('192.168.1.3', 19000)

  while True:
    data = await reader.readline()

    load_line = data.decode().rstrip()
    details = get_track_details(load_line)
    details = json.dumps(details)

    detals

    await websocket.send(details)

start_server = websockets.serve(time, 'localhost', 8765)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
