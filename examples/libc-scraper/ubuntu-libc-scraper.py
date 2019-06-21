#!/usr/bin/env python3

# Copyright (c) 2015-2020 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""
This script downloads .debs for the libc-dev packages off Ubuntu launchpad
leveraging high-performance asynchronous i/o.
"""

import sys, os
from bs4 import BeautifulSoup
import urllib

import aiohttp
import asyncio

packages = ['libc6-dev', 'libgcc-8-dev', 'libgcc-7-dev', 'libgcc-6-dev', 'libgcc-5-dev']

session, sem = None, None
async def must(f):
	global session, sem
	await sem.put(None)
	retries = 0
	while True:
		try:
			r = await f(session)
			if r.status == 200: break
			print(r.status)
		except: pass
		retries += 1
		if retries > 10:
			print('Maximum retry count exceeded')
			sys.exit(1)
		await asyncio.sleep(1.0)
	await sem.get()
	return r

async def get_html(url):
	async with (await must(lambda session: session.get(url))) as resp:
		sys.stderr.write('GET ' + url + '\n')
		return BeautifulSoup(await resp.text(), features="html.parser")

async def get_series():
	series = set()
	soup = await get_html('https://launchpad.net/ubuntu/+series')
	for strong in soup.find_all('strong'):
		for a in strong.find_all('a'):
			series.add(a['href'])
	return series

async def get_archs(series):
	soup = await get_html('https://launchpad.net' + series + '/+builds')
	for select in soup.find_all('select', {'id': 'arch_tag'}):
		for option in select.find_all('option'):
			if option['value'] == 'all': continue
			yield series + '/' + option['value']

async def get_versions(arch, package):
	soup = await get_html('https://launchpad.net' + arch + '/' + package)
	for tr in soup.find_all('tr'):
		if len(tr.find_all('td')) != 10: continue
		yield tr.find_all('td')[9].find_all('a')[0]['href']

async def get_deb_link(version):
	soup = await get_html('https://launchpad.net' + version)
	for a in soup.find_all('a', {'class': 'sprite'}):
		if a['href'].endswith('.deb'):
			return a['href']

async def download_deb(version, deb_url):
	filename = urllib.parse.urlparse(deb_url).path
	filename = filename[filename.rindex('/') + 1:]
	version = os.curdir + version
	filename = os.path.join(version, filename)
	if os.path.exists(filename):
		print('Skipping existing file', filename)
		return
	os.makedirs(version, exist_ok=True)
	async with (await must(lambda session: session.get(deb_url))) as resp:
		data = await resp.read()
		if not data:
			print('FAILED DOWNLOAD', filename, 'from', deb_url)
			return
		with open(filename, 'wb') as f:
			f.write(data)
	print('Downloaded', filename)

async def process_version(version):
	deb_link = await get_deb_link(version)
	if deb_link:
		await download_deb(version, deb_link)
	else:
		print('No .deb for', version)

async def process_arch(arch):
	await asyncio.gather(*[asyncio.create_task(process_version(version)) for package in packages async for version in get_versions(arch, package)])

async def process_series(series):
	await asyncio.gather(*[asyncio.create_task(process_arch(arch)) async for arch in get_archs(series)])

async def main():
	global session
	async with aiohttp.ClientSession() as session:
		await asyncio.gather(*[asyncio.create_task(process_series(series)) for series in await get_series()])

if __name__ == '__main__':
	MAX_CONCURRENT = 16
	loop = asyncio.get_event_loop()
	sem = asyncio.Queue(loop=loop, maxsize=MAX_CONCURRENT)
	loop.run_until_complete(main())
	loop.close()
