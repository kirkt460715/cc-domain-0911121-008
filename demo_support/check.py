import sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'portal'))
from server import start
from playwright.sync_api import sync_playwright
server,base=start()
try:
    with sync_playwright() as p,tempfile.TemporaryDirectory() as d:
        b=p.chromium.launch(headless=True,args=['--no-sandbox']);page=b.new_page(viewport={'width':1280,'height':720});page.goto(base)
        page.locator('#record[data-ready=true]').wait_for();assert page.locator('#record').get_attribute('data-revision')=='1'
        image=Path(d)/'page.png';page.screenshot(path=str(image));assert image.read_bytes().startswith(bytes([137,80,78,71]))
        assert '待保管员签收' in page.content();page.get_by_role('button',name='更新页面版本').click();page.locator('#record[data-revision="2"][data-ready=true]').wait_for()
        page.get_by_role('button',name='重新导航').click();page.wait_for_url('**/?visit=*');page.locator('#record[data-ready=true]').wait_for();b.close()
finally:server.shutdown();server.server_close()
print('动态页面实际浏览器：就绪、截图、DOM、版本切换和导航检查通过')
