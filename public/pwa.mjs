const installButton = document.querySelector('#pwa-install');
const installStatus = document.querySelector('#pwa-install-status');
const networkStatus = document.querySelector('#network-status');
const retryButton = document.querySelector('#connection-retry');
const displayMode = window.matchMedia('(display-mode: standalone)');
let installPrompt = null;
let installed = displayMode.matches || navigator.standalone === true;

function showInstalled() {
  installed = true;
  installPrompt = null;
  installButton.hidden = true;
  installStatus.textContent = '설치형 앱으로 사용할 수 있습니다. 서버 기기 승인은 별도로 확인해야 합니다.';
}

if (installed) showInstalled();
displayMode.addEventListener?.('change', event => {
  if (event.matches) showInstalled();
});

window.addEventListener('beforeinstallprompt', event => {
  if (installed) return;
  event.preventDefault();
  installPrompt = event;
  installButton.hidden = false;
  installStatus.textContent = '앱으로 설치할 수 있습니다. 설치는 기기 승인을 의미하지 않습니다.';
});

installButton.addEventListener('click', async () => {
  const prompt = installPrompt;
  if (!prompt) return;
  installPrompt = null;
  installButton.disabled = true;
  try {
    await prompt.prompt();
    const choice = await prompt.userChoice;
    if (!installed) {
      installStatus.textContent = choice.outcome === 'accepted'
        ? '설치 요청을 보냈습니다. 설치 완료와 서버 기기 승인은 별도로 확인해야 합니다.'
        : '설치를 취소했습니다. 일반 웹사이트로 계속 이용할 수 있습니다.';
    }
  } catch {
    if (!installed) installStatus.textContent = '설치를 진행하지 못했습니다. 일반 웹사이트로 계속 이용할 수 있습니다.';
  } finally {
    installButton.disabled = false;
    installButton.hidden = !installPrompt || installed;
  }
});
window.addEventListener('appinstalled', showInstalled);

function showNetwork() {
  const offline = navigator.onLine === false;
  networkStatus.hidden = false;
  retryButton.hidden = false;
  retryButton.disabled = offline;
  networkStatus.textContent = offline
    ? '오프라인에서는 보호 자료를 읽을 수 없습니다. 연결 후 다시 확인하면 재인증이 필요할 수 있습니다.'
    : '네트워크가 연결되었습니다. 다시 확인하여 로그인 상태를 검증하세요.';
}
window.addEventListener('offline', showNetwork);
window.addEventListener('online', showNetwork);
retryButton.addEventListener('click', () => window.location.reload());
if (navigator.onLine === false) showNetwork();

function registerOfflineSupport() {
  if (!('serviceWorker' in navigator) || !window.isSecureContext) return;
  navigator.serviceWorker.register('/sw.js', { scope: '/', updateViaCache: 'none' })
    .catch(() => {
      if (!installed && !installPrompt) {
        installStatus.textContent = '오프라인 안내를 준비하지 못했습니다. 온라인에서는 일반 웹사이트로 이용할 수 있습니다.';
      }
    });
}
if (document.readyState === 'complete') registerOfflineSupport();
else window.addEventListener('load', registerOfflineSupport, { once: true });
