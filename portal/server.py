import argparse,json,threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
ROOT=Path(__file__).resolve().parent
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        path=urlsplit(self.path).path
        if path=='/':data=(ROOT/'index.html').read_bytes();kind='text/html; charset=utf-8';status=200
        elif path=='/page.js':data=(ROOT/'page.js').read_bytes();kind='application/javascript';status=200
        elif path=='/content':data=json.dumps({'revision':self.server.revision,'title':'合成设备交接记录','text':'设备 A 已完成检查，待保管员签收。'},ensure_ascii=False).encode();kind='application/json';status=200
        elif path=='/missing-image':data=b'';kind='image/png';status=404
        else:data=b'not found';kind='text/plain';status=404
        self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self):
        if self.path=='/revision':self.server.revision+=1;self.send_response(204);self.end_headers()
        else:self.send_error(404)
def start():
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.revision=1;threading.Thread(target=server.serve_forever,daemon=True).start();return server,'http://127.0.0.1:'+str(server.server_port)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=8787);a=p.parse_args()
    with ThreadingHTTPServer(('127.0.0.1',a.port),Handler) as s:s.revision=1;print('证据演练页',s.server_address,flush=True);s.serve_forever()
