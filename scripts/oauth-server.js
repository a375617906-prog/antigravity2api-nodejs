import http from 'http';
import { URL } from 'url';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import axios from 'axios';
import log from '../src/utils/logger.js';
import config from '../src/config/config.js';
import { generateProjectId } from '../src/utils/idGenerator.js';
import tokenManager from '../src/auth/token_manager.js';
import { OAUTH_CONFIG, OAUTH_SCOPES } from '../src/constants/oauth.js';
import { buildAxiosRequestConfig } from '../src/utils/httpClient.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// 账号文件路径保持不变，仅用于日志展示，具体读写交给 TokenManager 处理
const ACCOUNTS_FILE = path.join(__dirname, '..', 'data', 'accounts.json');
const STATE = crypto.randomUUID();

const SCOPES = OAUTH_SCOPES;

function generateAuthUrl(port) {
  const params = new URLSearchParams({
    access_type: 'offline',
    client_id: OAUTH_CONFIG.CLIENT_ID,
    prompt: 'consent',
    redirect_uri: `http://localhost:${port}/oauth-callback`,
    response_type: 'code',
    scope: SCOPES.join(' '),
    state: STATE
  });
  return `${OAUTH_CONFIG.AUTH_URL}?${params.toString()}`;
}

async function exchangeCodeForToken(code, port) {
  const postData = new URLSearchParams({
    code,
    client_id: OAUTH_CONFIG.CLIENT_ID,
    client_secret: OAUTH_CONFIG.CLIENT_SECRET,
    redirect_uri: `http://localhost:${port}/oauth-callback`,
    grant_type: 'authorization_code'
  });
  
  const response = await axios(buildAxiosRequestConfig({
    method: 'POST',
    url: OAUTH_CONFIG.TOKEN_URL,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: postData.toString(),
    timeout: config.timeout
  }));
  
  return response.data;
}

async function fetchUserEmail(accessToken) {
  const response = await axios(buildAxiosRequestConfig({
    method: 'GET',
    url: 'https://www.googleapis.com/oauth2/v2/userinfo',
    headers: {
      'Host': 'www.googleapis.com',
      'User-Agent': 'Go-http-client/1.1',
      'Authorization': `Bearer ${accessToken}`,
      'Accept-Encoding': 'gzip'
    },
    timeout: config.timeout
  }));
  return response.data?.email;
}

const server = http.createServer((req, res) => {
  const port = server.address().port;
  const url = new URL(req.url, `http://localhost:${port}`);
  
  if (url.pathname === '/oauth-callback') {
    const code = url.searchParams.get('code');
    const error = url.searchParams.get('error');
    
    if (code) {
      log.info('收到授权码，正在交换 Token...');
      exchangeCodeForToken(code, port).then(async (tokenData) => {
        const account = {
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token,
          expires_in: tokenData.expires_in,
          timestamp: Date.now()
        };
        
        try {
          const email = await fetchUserEmail(account.access_token);
          if (email) {
            account.email = email;
            log.info('获取到用户邮箱: ' + email);
          }
        } catch (err) {
          log.warn('获取用户邮箱失败:', err.message);
        }
        
        if (config.skipProjectIdFetch) {
          account.projectId = generateProjectId();
          account.enable = true;
          log.info('已跳过API验证，使用随机生成的projectId: ' + account.projectId);
        } else {
          log.info('正在验证账号资格...');
          try {
            const projectId = await tokenManager.fetchProjectId({ access_token: account.access_token });
            if (projectId === undefined) {
              log.warn('该账号无资格使用（无法获取projectId），已跳过保存');
              res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
              res.end('<h1>账号无资格</h1><p>该账号无法获取projectId，未保存。</p>');
              setTimeout(() => server.close(), 1000);
              return;
            }
            account.projectId = projectId;
            account.enable = true;
            log.info('账号验证通过');
          } catch (err) {
            log.error('验证账号资格失败:', err.message);
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end('<h1>验证失败</h1><p>无法验证账号资格，请查看控制台。</p>');
            setTimeout(() => server.close(), 1000);
            return;
          }
        }
        
        const result = tokenManager.addToken(account);
        if (result.success) {
          log.info(`Token 已保存到 ${ACCOUNTS_FILE}`);
        } else {
          log.error('保存 Token 失败:', result.message);
        }
        
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<h1>授权成功！</h1><p>Token 已保存，可以关闭此页面。</p>');
        
        setTimeout(() => server.close(), 1000);
      }).catch(err => {
        log.error('Token 交换失败:', err.message);
        
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<h1>Token 获取失败</h1><p>查看控制台错误信息</p>');
        
        setTimeout(() => server.close(), 1000);
      });
    } else {
      log.error('授权失败:', error || '未收到授权码');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>授权失败</h1>');
      setTimeout(() => server.close(), 1000);
    }
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

server.listen(0, () => {
  const port = server.address().port;
  const authUrl = generateAuthUrl(port);
  log.info(`服务器运行在 http://localhost:${port}`);
  log.info('请在浏览器中打开以下链接进行登录：');
  console.log(`\n${authUrl}\n`);
  log.info('等待授权回调...');
});
