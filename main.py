import asyncio
import aiohttp
import logging
import random
import time
import json
from aiohttp import ClientError
from web3 import Web3
from eth_account.messages import encode_defunct
from fake_useragent import UserAgent
import colorlog 

handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s%(asctime)s - %(levelname)s - %(message)s',  # лог с цветом
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
    }
))
logger = colorlog.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class WalletProcessor:
    def __init__(self, private_key, invite_code, proxy, delay_min, delay_max):
        self.private_key = private_key
        self.invite_code = invite_code
        self.proxy = proxy
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.wallet_address = self.get_wallet_address()
        self.user_agent = UserAgent().random 

    def get_wallet_address(self):
        w3 = Web3()
        account = w3.eth.account.from_key(self.private_key)
        return account.address

    def create_signature(self, message):
        w3 = Web3()
        encoded_message = encode_defunct(text=message)
        signed_message = w3.eth.account.sign_message(encoded_message, private_key=self.private_key)
        return signed_message.signature.hex()

    def parse_proxy(self):
        host, port, username, password = self.proxy.split(':')
        return f'http://{username}:{password}@{host}:{port}'

    async def make_request(self, session, url, payload):
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-GB,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://balance.fun',
            'Referer': f'https://balance.fun/account?invite_code={self.invite_code}',
            'User-Agent': self.user_agent,
            'DNT': '1',  # Don't track
            'Cache-Control': 'no-cache',
            'Upgrade-Insecure-Requests': '1'
        }
        logging.info(f"Кошелек {self.wallet_address} отправляет запрос на {url}.")
        async with session.post(url, data=payload, headers=headers) as response:
            logger.info(f"Статус ответа: {response.status}")
            
            # Логируем все заголовки ответа
            logger.info(f"Заголовки ответа: {response.headers}")

            # Проверяем статус ответа
            if response.status == 200:
                data = await response.json()
                logging.info(f"Кошелек {self.wallet_address} получил ответ: {data} на запрос {url}.")
                
                cookies = response.cookies
                if cookies:
                    logger.info(f"Получены cookies: {cookies}")
                else:
                    logger.warning(f"Cookies отсутствуют в ответе от {url}")                
                
                return data
            else:
                logging.error(f"Ошибка {response.status}: Кошелек {self.wallet_address} не получил валидный ответ на запрос {url}.")
                return None

    async def process(self):
        message = "You hereby confirm that you are the owner of this connected wallet. This is a safe and gasless transaction to verify your ownership. Signing this message will not give Balance.fun permission to make transactions with your wallet."
        signature = self.create_signature(message)

        proxy_url = self.parse_proxy() 
        logging.info(f"Начал работу с кошельком {self.wallet_address}. Прокси: {proxy_url}")

        try:
            connector = aiohttp.TCPConnector()

            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=30)) as session:
                session._default_headers = {"Proxy": proxy_url}
                
                payload = {
                    'wallet_signature': signature,
                    'wallet': self.wallet_address,
                    'invite_code': self.invite_code,
                    'full_message': '',
                    'public_key': '',
                    'chain_type': ''
                }

                access_token_response = await self.make_request(session, 'https://balance.fun/api/wallet_login', payload)

                if access_token_response and 'data' in access_token_response:
                    access_token = access_token_response['data']['access_token']
                    session.headers.update({'Authorization': access_token})

                    await self.execute_requests(session)
                    await self.send_redirect_follow(session)
                    await self.credit_refresh(session)
                else:
                    logging.error(f"Не удалось получить токен доступа для кошелька {self.wallet_address}. Пропускаем кошелек.")
                    
        except (ClientError, Exception) as e:
            logging.error(f"Ошибка с прокси {self.proxy}: {e}. Пропускаем этот прокси.")

    async def execute_requests(self, session):
        urls = [
            'https://balance.fun/api/credit_refresh',

            'https://example.com/api/nikepro_pickme',    # Добавляем лишние запросы 

            'https://balance.fun/api/login_refresh',
            'https://balance.fun/api/invite_list',

            'https://jsonplaceholder.typicode.com/todos/1',   # Добавляем лишние запросы 
            
            'https://balance.fun/api/token_list',
            'https://balance.fun/api/nft_list'

            'https://example.com/api/random_check',   # Добавляем лишние запросы 

        ]
        for url in urls:
            payload = {'wallet': self.wallet_address}

            logging.info(f"Отправляем запрос на URL: {url}")


            if 'example.com' in url or 'jsonplaceholder.typicode.com' in url:  # Для лишних запросов пустые данные
                payload = {}  # Пустой payload 
            
            await self.make_request(session, url, payload)
            delay = random.uniform(1, 5)
            logging.info(f"Задержка между запросами: {delay} секунд.")
            await asyncio.sleep(delay)  # Задержка между запросами

    async def send_redirect_follow(self, session):
        url = 'https://balance.fun/api/redirect_follow'
        payload = {
            'follow_type': 2,
            'wallet': self.wallet_address
        }
        response = await self.make_request(session, url, payload)

        if response and response.get('code') == 0:
            logging.info(f"Запрос на квест твиттера для кошелька {self.wallet_address} выполнен успешно, получено +200 кредитов.")
        else:
            logging.error(f"Не удалось выполнить квест твиттера для кошелька {self.wallet_address}.")

    async def credit_refresh(self, session):
        url = 'https://balance.fun/api/credit_refresh'
        payload = {'wallet': self.wallet_address}
        await self.make_request(session, url, payload)

class WalletManager:
    def __init__(self, keys_file, proxy_file, config_file):
        self.private_keys = self.read_file(keys_file)
        self.proxies = self.read_file(proxy_file)
        self.config = self.load_config(config_file)

        if len(self.private_keys) > len(self.proxies):
            raise ValueError("Количество кошельков превышает количество доступных прокси. Добавьте больше прокси.")
        
    def read_file(self, filename):
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def load_config(self, config_file):
        with open(config_file, 'r') as f:
            return json.load(f)

    async def run(self):
        delay_min = self.config["delay_min"]
        delay_max = self.config["delay_max"]
        invite_code = self.config["invite_code"]

        for private_key, proxy in zip(self.private_keys, self.proxies):
            processor = WalletProcessor(private_key, invite_code, proxy, delay_min, delay_max)
            await processor.process()
            delay = random.randint(delay_min, delay_max)
            logging.info(f"Задержка перед следующим кошельком: {delay} секунд.")
            await asyncio.sleep(delay)
               
        logger.info("Все кошельки обработаны. Скрипт завершил работу.")

if __name__ == "__main__":
    manager = WalletManager("pkey.txt", "proxy.txt", "config.json")
    asyncio.run(manager.run())
