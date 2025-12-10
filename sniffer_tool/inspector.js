// 全局状态
window.inspectorEnabled = false;
window.hoveredElement = null;

// 高亮样式
const style = document.createElement('style');
style.textContent = `
    .gov-inspector-highlight {
        outline: 2px solid #e10f0fff !important;
        background-color: rgba(0, 255, 242, 0.47) !important;
        cursor: crosshair !important;
    }
`;
document.head.appendChild(style);

// 辅助函数：生成 XPath
function getXPath(element) {
    if (element.id !== '')
        return '//*[@id="' + element.id + '"]';
    
    if (element === document.body)
        return '/html/body';

    var ix = 0;
    var siblings = element.parentNode.childNodes;
    for (var i = 0; i < siblings.length; i++) {
        var sibling = siblings[i];
        if (sibling === element)
            return getXPath(element.parentNode) + '/' + element.tagName.toLowerCase() + '[' + (ix + 1) + ']';
        if (sibling.nodeType === 1 && sibling.tagName === element.tagName)
            ix++;
    }
}

// 辅助函数：生成智能 XPath（最短唯一）
function getSmartXPath(element) {
    if (element.id !== '')
        return '//*[@id="' + element.id + '"]';
    
    const paths = [];
    
    // 1. 尝试基于 Class
    if (element.className && typeof element.className === 'string') {
        const classes = element.className.trim().split(/\s+/);
        for (let cls of classes) {
            if (!cls) continue;
            // 如果需要，跳过通用工具类
            const p = `//${element.tagName.toLowerCase()}[contains(@class, '${cls}')]`;
            // 检查唯一性
            const count = document.evaluate("count(" + p + ")", document, null, XPathResult.ANY_TYPE, null).numberValue;
            if (count === 1) return p;
        }
    }
    
    return getXPath(element);
}

// 辅助函数：验证选择器（AMH 稳定性检查）
function validateSelector(xpath) {
    try {
        const result = document.evaluate(xpath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
        return result.snapshotLength;
    } catch (e) {
        return 0;
    }
}

// 事件监听器
document.addEventListener('mouseover', function(e) {
    if (!window.inspectorEnabled) return;
    
    e.preventDefault();
    e.stopPropagation();
    
    if (window.hoveredElement) {
        window.hoveredElement.classList.remove('gov-inspector-highlight');
    }
    
    window.hoveredElement = e.target;
    window.hoveredElement.classList.add('gov-inspector-highlight');
    
    // 可选：将悬停信息发送到 Python 进行“实时预览”
}, true);

document.addEventListener('mouseout', function(e) {
    if (!window.inspectorEnabled) return;
    if (window.hoveredElement) {
        window.hoveredElement.classList.remove('gov-inspector-highlight');
        window.hoveredElement = null;
    }
}, true);

document.addEventListener('click', function(e) {
    if (!window.inspectorEnabled) return;
    
    e.preventDefault();
    e.stopPropagation();
    
    const target = e.target;
    const xpath = getXPath(target);
    const smartXpath = getSmartXPath(target);
    
    // AMH 稳定性检查
    const xpathCount = validateSelector(xpath);
    const smartXpathCount = validateSelector(smartXpath);
    
    const text = target.innerText || target.textContent;
    const tagName = target.tagName;
    const attributes = {};
    for (let i = 0; i < target.attributes.length; i++) {
        attributes[target.attributes[i].name] = target.attributes[i].value;
    }

    const data = {
        xpath: xpath,
        smart_xpath: smartXpath,
        xpath_count: xpathCount,
        smart_xpath_count: smartXpathCount,
        tag: tagName,
        text: text.substring(0, 100), // 预览
        attributes: attributes,
        outer_html: target.outerHTML.substring(0, 500)
    };
    
    // 发送到 Python
    if (window.bridge) {
        window.bridge.receive_selection(JSON.stringify(data));
    } else {
        console.log("Bridge not found", data);
    }
    
}, true);

// 初始化 Bridge
function initBridge() {
    if (typeof qt === 'undefined' || typeof qt.webChannelTransport === 'undefined') {
        console.log("qt.webChannelTransport not ready, waiting...");
        setTimeout(initBridge, 100);
        return;
    }
    
    if (typeof QWebChannel === 'undefined') {
        console.log("QWebChannel class not ready, waiting...");
        setTimeout(initBridge, 100);
        return;
    }

    try {
        new QWebChannel(qt.webChannelTransport, function(channel) {
            window.bridge = channel.objects.bridge;
            console.log("Bridge initialized successfully");
        });
    } catch (e) {
        console.error("Bridge init error: " + e);
        setTimeout(initBridge, 500);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initBridge);
} else {
    initBridge();
}

console.log("Inspector Loaded");
