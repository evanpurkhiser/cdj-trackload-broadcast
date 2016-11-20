#!/usr/bin/env python3

import asyncio
import websockets
import mutagen
import json
import base64
import os
import signal
import optparse

class TrackloadWebsocketServer(object):
    """
    This is a websocket server that connects to the CDJ broadcast server to be
    notified of when a track is loaded. The track details will be queried from
    ID3 tags and sent to the web socket as JSON.
    """
    def __init__(self, music_path, websocket_server, broadcast_server):
        """Initializes the trackload websocket server.q 

        - music_path:       Location of the music files on the moachine.
        - websocket_server: Tuple of host and port for the websocket server.
        - broadcast_server: Tuple of host and port of the broadcast server.
        """
        self.music_path = music_path
        self.websocket_server = websocket_server
        self.broadcast_server = broadcast_server

    def __track_details(self, load_line):
        """Given a track load line from the broadcast server, construct the
        details of the loaded track.

        - load_line: Should be in the format <deck_id>:<track_path>
        """
        deck_id, path = load_line.split(':', 1)
        full_path = os.path.join(self.music_path, path)

        track = mutagen.File(full_path).tags

        # Convert the artwork into base 64
        art = track.getall('APIC')
        artwork = None

        if len(art) > 0:
            data = base64.b64encode(art[0].data).decode('utf-8')
            mime = art[0].mime

            artwork = 'data:{mime};base64,{data}'.format(mime=mime, data=data)

        return {
            'deck_id': int(deck_id),
            'artist':  track['TPE1'].text[0],
            'title':   track['TIT2'].text[0],
            'album':   track['TALB'].text[0] if 'TALB' in track else None,
            'key':     track['TKEY'].text[0] if 'TKEY' in track else None,
            'label':   track['TPUB'].text[0] if 'TPUB' in track else None,
            'release': track['COMM::XXX'].text[0] if 'COMM::XXX' in track else None,
            'year':    track['TDRC'].text[0].get_text() if 'TDRC' in track else None,
            'artwork': artwork,
        }

    async def trackload(self, websocket, path):
        """Coroutine that will wait for tracks to be loaded from the broadcast
        server, promptly sending JSON to the websocket with information about
        the track that was loaded.
        """
        reader, writer = await asyncio.open_connection(*self.broadcast_server)

        while True:
            data = await reader.readline()

            load_line = data.decode().rstrip()
            details = self.__track_details(load_line)
            details = json.dumps(details)

            await websocket.send(details)

    def start(self):
        """Start the server in the asyncio event loop.
        """
        server = websockets.serve(self.trackload, *self.websocket_server)

        asyncio.get_event_loop().run_until_complete(server)

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-m', '--music-path', dest='music_path')

    parser.add_option('-s', '--broadcast-addr', dest='bc_host')
    parser.add_option('-p', '--broadcast-port', dest='bc_port', default=19000)

    opts, _ = parser.parse_args()

    ws_server  = ('localhost', 8008)
    bc_server  = (opts.bc_host, opts.bc_port)

    tracklistServer = TrackloadWebsocketServer(opts.music_path, ws_server, bc_server)
    tracklistServer.start()

    asyncio.get_event_loop().run_forever()
