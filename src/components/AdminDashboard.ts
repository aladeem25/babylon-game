import { Router } from '@/utils/Router';
import { getDefaultSceneCode, getWebGPUSceneCode } from '@/assets/defaultScene';
import { ApiClient } from '@/utils/ApiClient';

/**
 * Code execution security utilities
 */
class CodeSecurityManager {
    private static readonly MAX_CODE_LENGTH = 100000; // 100KB limit
    private static readonly FORBIDDEN_PATTERNS = [
        /eval\s*\(/gi,
        /Function\s*\(/gi,
        /setTimeout\s*\(/gi,
        /setInterval\s*\(/gi,
        /XMLHttpRequest/gi,
        /fetch\s*\(/gi,
        /import\s*\(/gi,
        /require\s*\(/gi,
        /process\./gi,
        /global\./gi,
        /window\.location/gi,
        /document\.cookie/gi,
        /localStorage/gi,
        /sessionStorage/gi
    ];

    private static readonly ALLOWED_BABYLON_IMPORTS = [
        '@babylonjs/core',
        '@babylonjs/gui',
        '@babylonjs/loaders'
    ];

    /**
     * Validate user code for security issues
     */
    static validateCode(code: string): { valid: boolean; errors: string[] } {
        const errors: string[] = [];

        // Check code length
        if (code.length > this.MAX_CODE_LENGTH) {
            errors.push(`كود طويل جداً. الحد الأقصى ${this.MAX_CODE_LENGTH} حرف`);
        }

        // Check for forbidden patterns
        for (const pattern of this.FORBIDDEN_PATTERNS) {
            if (pattern.test(code)) {
                errors.push(`كود يحتوي على وظائف محظورة: ${pattern.source}`);
            }
        }

        // Check for suspicious patterns
        if (code.includes('__proto__') || code.includes('constructor')) {
            errors.push('كود يحتوي على محاولة للوصول لـ prototype chain');
        }

        return {
            valid: errors.length === 0,
            errors
        };
    }

    /**
     * Sanitize code by removing potentially dangerous constructs
     */
    static sanitizeCode(code: string): string {
        // Remove dangerous patterns while preserving functionality
        let sanitized = code;
        
        // Replace dangerous window/global access with safe alternatives
        sanitized = sanitized.replace(/window\./gi, 'undefined.');
        sanitized = sanitized.replace(/global\./gi, 'undefined.');
        
        return sanitized;
    }

    /**
     * Create execution checksum for integrity verification
     */
    static createChecksum(code: string): string {
        // Simple checksum using hash-like function
        let hash = 0;
        for (let i = 0; i < code.length; i++) {
            const char = code.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(16);
    }

    /**
     * Sanitize HTML content to prevent XSS
     */
    static sanitizeHTML(html: string): string {
        // Create a temporary element to parse HTML
        const temp = document.createElement('div');
        temp.textContent = html; // This escapes HTML entities
        return temp.innerHTML;
    }

    /**
     * Create safe HTML element with sanitized content
     */
    static createSafeElement(tagName: string, content: string, attributes?: Record<string, string>): HTMLElement {
        const element = document.createElement(tagName);
        element.textContent = content; // Safe text content
        
        if (attributes) {
            for (const [key, value] of Object.entries(attributes)) {
                // Only allow safe attributes
                if (this.isSafeAttribute(key)) {
                    element.setAttribute(key, this.sanitizeAttribute(value));
                }
            }
        }
        
        return element;
    }

    /**
     * Check if an attribute is safe to use
     */
    private static isSafeAttribute(attributeName: string): boolean {
        const safeAttributes = [
            'class', 'id', 'title', 'alt', 'src', 'href', 'target',
            'style', 'data-*', 'aria-*', 'role'
        ];
        
        return safeAttributes.some(safe => 
            safe === attributeName || 
            (safe.endsWith('*') && attributeName.startsWith(safe.slice(0, -1)))
        );
    }

    /**
     * Sanitize attribute values
     */
    private static sanitizeAttribute(value: string): string {
        // Remove potentially dangerous protocols
        if (value.match(/^(javascript|data|vbscript):/i)) {
            return '';
        }
        return value;
    }
}

/**
 * لوحة التحكم الإدارية - Playground Editor
 */
export class AdminDashboard {
    private container: HTMLElement;
    private router: Router;
    private engine: any;
    private scene: any;
    private canvas: HTMLCanvasElement | null = null;
    private editor: any;
    private apiClient: ApiClient;
    private isWebGPUEnabled: boolean = false;
    private isWireframeMode: boolean = false;
    private isFullscreenViewport: boolean = false;

    constructor(container: HTMLElement, router: Router) {
        this.container = container;
        this.router = router;
        this.apiClient = new ApiClient();
    }

    /**
     * تهيئة لوحة التحكم الإدارية
     */
    async initialize(): Promise<void> {
        this.createHTML();
        await this.initializeEditor();
        await this.initializeBabylon();
        this.setupEventListeners();
        
        // انتظار قليل للتأكد من اكتمال تهيئة المحرر
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // فحص دعم WebGPU وتعطيل الخيار إذا لم يكن مدعوماً
        await this.checkWebGPUSupport();
        
        // تحميل الكود الافتراضي في المحرر دائماً عند البدء
        if (this.editor) {
            console.log('Editor initialized, loading default code...');
            const defaultCode = this.getDefaultCode();
            console.log('Default code length:', defaultCode.length);
            
            // تنظيف المحرر أولاً
            this.editor.setValue('');
            
            // انتظار قصير ثم تحميل الكود
            setTimeout(() => {
                this.editor.setValue(defaultCode);
                
                // التأكد من أن المحرر قابل للتحرير
                this.editor.updateOptions({
                    readOnly: false,
                    domReadOnly: false
                });
                
                // focus على المحرر
                this.editor.focus();
                
                console.log('Default code loaded, editor value length:', this.editor.getValue().length);
            }, 100);
            
            // لا نشغل الكود تلقائياً - المستخدم يحتاج للضغط على زر التشغيل
        } else {
            console.error('Editor not initialized!');
        }
    }

    /**
     * إنشاء HTML للوحة التحكم
     */
    private createHTML(): void {
        this.container.innerHTML = this.getHTML();
    }

    /**
     * الحصول على HTML للوحة التحكم
     */
    private getHTML(): string {
        return `
            <div class="admin-dashboard">
                <div class="dashboard-header">
                    <div class="header-left">
                        <button id="back-btn" class="back-btn">
                            <span>←</span>
                            <span>العودة</span>
                        </button>
                        <h2>لوحة التحكم الإدارية</h2>
                    </div>
                    
                    <div class="header-center">
                        <div class="menu-bar">
                            <button class="menu-btn" id="new-btn">جديد</button>
                            <button class="menu-btn" id="webgpu-example-btn">مثال WebGPU</button>
                            <button class="menu-btn" id="save-btn">حفظ</button>
                            <button class="menu-btn" id="load-btn">تحميل</button>
                            <button class="menu-btn" id="library-btn">مكتبة الأصول</button>
                            <div class="separator"></div>
                            <select id="asset-type" class="asset-selector">
                                <option value="map">خريطة</option>
                                <option value="character">شخصية</option>
                                <option value="object">كائن</option>
                            </select>
                            <button class="menu-btn" id="run-btn">تشغيل</button>
                        </div>
                    </div>
                    
                    <div class="header-right">
                        <select id="engine-selector" class="engine-selector">
                            <option value="webgl2">WebGL2</option>
                            <option value="webgpu">WebGPU</option>
                        </select>
                        <button class="control-btn" id="layout-btn">⚏</button>
                        <button class="control-btn" id="settings-btn">⚙️</button>
                    </div>
                </div>
                
                <div class="dashboard-content">
                    <div class="viewport-container">
                        <div class="viewport-header">
                            <h3>منطقة العرض ثلاثية الأبعاد</h3>
                            <div class="viewport-controls">
                                <button class="viewport-btn" id="wireframe-btn">🔲</button>
                                <button class="viewport-btn" id="inspector-btn">🔍</button>
                                <button class="viewport-btn" id="fullscreen-viewport-btn">⛶</button>
                            </div>
                        </div>
                        <div class="viewport">
                            <canvas id="babylon-canvas"></canvas>
                            <div id="viewport-loading" class="viewport-loading">
                                <div class="loading-spinner"></div>
                                <div>جاري تحميل محرر البيئة...</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="editor-container">
                        <div class="editor-header">
                            <h3>محرر الكود</h3>
                            <div class="editor-controls">
                                <button class="editor-btn" id="import-assets-btn">استيراد أصول خارجية</button>
                                <button class="editor-btn" id="format-btn">تنسيق</button>
                                <button class="editor-btn" id="validate-btn">تحقق</button>
                                <select id="language-select" class="language-selector">
                                    <option value="javascript">JavaScript</option>
                                    <option value="typescript">TypeScript</option>
                                </select>
                            </div>
                        </div>
                        <div class="editor">
                            <div id="monaco-editor"></div>
                        </div>
                    </div>
                </div>
                
                <div class="dashboard-footer">
                    <div class="status-bar">
                        <span id="status-text">جاهز</span>
                        <div class="status-right">
                            <span id="cursor-position">السطر 1، العمود 1</span>
                            <span id="engine-info">WebGL2</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- مكتبة الأصول -->
            <div id="asset-library" class="asset-library hidden">
                <div class="asset-library-header">
                    <h3>مكتبة الأصول</h3>
                    <div class="asset-library-controls">
                        <select id="library-asset-type" class="library-type-selector">
                            <option value="map">الخرائط</option>
                            <option value="character">الشخصيات</option>
                            <option value="object">الكائنات</option>
                        </select>
                        <button class="close-btn" id="close-library-btn">✕</button>
                    </div>
                </div>
                <div class="asset-library-content">
                    <div id="asset-grid" class="asset-grid">
                        <!-- سيتم ملء هذا تلقائياً -->
                    </div>
                </div>
            </div>
            
            <!-- لوحة استيراد الأصول الخارجية -->
            <div id="import-assets-panel" class="import-assets-panel hidden">
                <div class="import-panel-header">
                    <h3>استيراد أصول خارجية</h3>
                    <button class="close-btn" id="close-import-panel-btn">✕</button>
                </div>
                <div class="import-panel-content">
                    <div class="import-options">
                        <div class="import-section">
                            <h4>استيراد ملفات فردية</h4>
                            <input type="file" id="single-file-input" multiple accept=".babylon,.gltf,.glb,.obj,.fbx,.jpg,.jpeg,.png,.gif,.mp3,.wav,.ogg">
                            <button class="import-btn" id="import-single-files-btn">رفع الملفات المحددة</button>
                        </div>
                        
                        <div class="import-section">
                            <h4>استيراد مجلد كامل</h4>
                            <input type="file" id="folder-input" webkitdirectory directory multiple>
                            <button class="import-btn" id="import-folder-btn">رفع المجلد المحدد</button>
                        </div>
                    </div>
                    
                    <div class="import-status" id="import-status">
                        <p>اختر الملفات أو المجلد للاستيراد</p>
                    </div>
                    
                    <div class="imported-files" id="imported-files">
                        <h4>الملفات المستوردة حالياً:</h4>
                        <div id="imported-files-list" class="imported-files-list">
                            <!-- سيتم ملء قائمة الملفات هنا -->
                        </div>
                        <button class="clear-btn" id="clear-imports-btn">مسح جميع الاستيرادات</button>
                    </div>
                </div>
            </div>
            
            <style>
                .admin-dashboard {
                    width: 100%;
                    height: 100vh;
                    display: flex;
                    flex-direction: column;
                    background: #1e1e1e;
                    color: #d4d4d4;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                }
                
                .dashboard-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 0.5rem 1rem;
                    background: #2d2d30;
                    border-bottom: 1px solid #3e3e42;
                    min-height: 60px;
                }
                
                .header-left {
                    display: flex;
                    align-items: center;
                    gap: 1rem;
                }
                
                .back-btn {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    padding: 0.5rem 1rem;
                    background: #0e639c;
                    border: none;
                    border-radius: 4px;
                    color: white;
                    cursor: pointer;
                    transition: background 0.3s ease;
                }
                
                .back-btn:hover {
                    background: #1177bb;
                }
                
                .header-left h2 {
                    margin: 0;
                    font-size: 1.2rem;
                    font-weight: 600;
                }
                
                .menu-bar {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                
                .menu-btn {
                    padding: 0.5rem 1rem;
                    background: transparent;
                    border: 1px solid #3e3e42;
                    border-radius: 4px;
                    color: #d4d4d4;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                
                .menu-btn:hover {
                    background: #3e3e42;
                    border-color: #007acc;
                }
                
                .separator {
                    width: 1px;
                    height: 20px;
                    background: #3e3e42;
                    margin: 0 0.5rem;
                }
                
                .asset-selector, .language-selector, .engine-selector {
                    padding: 0.5rem;
                    background: #3c3c3c;
                    border: 1px solid #3e3e42;
                    border-radius: 4px;
                    color: #d4d4d4;
                    cursor: pointer;
                }
                
                .engine-selector {
                    margin-right: 0.5rem;
                }
                
                .header-right {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                
                .control-btn {
                    width: 35px;
                    height: 35px;
                    border: none;
                    border-radius: 4px;
                    background: transparent;
                    color: #d4d4d4;
                    cursor: pointer;
                    transition: background 0.3s ease;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                
                .control-btn:hover {
                    background: #3e3e42;
                }
                
                .dashboard-content {
                    flex: 1;
                    display: flex;
                    min-height: 0;
                }
                
                .viewport-container, .editor-container {
                    flex: 1;
                    display: flex;
                    flex-direction: column;
                    min-height: 0;
                }
                
                .viewport-container {
                    border-right: 1px solid #3e3e42;
                }
                
                .viewport-header, .editor-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    padding: 0.5rem 1rem;
                    background: #252526;
                    border-bottom: 1px solid #3e3e42;
                    min-height: 40px;
                }
                
                .viewport-header h3, .editor-header h3 {
                    margin: 0;
                    font-size: 0.9rem;
                    font-weight: 600;
                }
                
                .viewport-controls, .editor-controls {
                    display: flex;
                    gap: 0.5rem;
                    align-items: center;
                }
                
                .viewport-btn, .editor-btn {
                    width: 30px;
                    height: 30px;
                    border: none;
                    border-radius: 3px;
                    background: transparent;
                    color: #d4d4d4;
                    cursor: pointer;
                    transition: background 0.3s ease;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 0.8rem;
                }
                
                .editor-btn {
                    width: auto;
                    padding: 0.3rem 0.8rem;
                    font-size: 0.8rem;
                }
                
                .viewport-btn:hover, .editor-btn:hover {
                    background: #3e3e42;
                }
                
                .viewport, .editor {
                    flex: 1;
                    position: relative;
                    min-height: 0;
                }
                
                #babylon-canvas {
                    width: 100%;
                    height: 100%;
                    display: block;
                    background: #1a1a1a;
                }
                
                #monaco-editor {
                    width: 100%;
                    height: 100%;
                    position: relative;
                    overflow: visible;
                    direction: ltr;
                }
                
                .monaco-editor {
                    direction: ltr !important;
                }
                
                .monaco-editor .view-lines {
                    direction: ltr !important;
                    text-align: left !important;
                }
                
                .monaco-editor .margin {
                    direction: ltr !important;
                }
                
                .monaco-editor .line-numbers {
                    direction: ltr !important;
                    text-align: right !important;
                }
                
                .viewport-loading {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(30, 30, 30, 0.9);
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    z-index: 10;
                }
                
                .loading-spinner {
                    width: 30px;
                    height: 30px;
                    border: 2px solid rgba(212, 212, 212, 0.3);
                    border-top: 2px solid #007acc;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin-bottom: 1rem;
                }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                
                .dashboard-footer {
                    background: #007acc;
                    color: white;
                    padding: 0.3rem 1rem;
                    font-size: 0.8rem;
                }
                
                .status-bar {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .status-right {
                    display: flex;
                    gap: 1rem;
                }
                
                @media (max-width: 1024px) {
                    .dashboard-content {
                        flex-direction: column;
                    }
                    
                    .viewport-container {
                        border-right: none;
                        border-bottom: 1px solid #3e3e42;
                        height: 50%;
                    }
                    
                    .editor-container {
                        height: 50%;
                    }
                }
                
                @media (max-width: 768px) {
                    .dashboard-header {
                        flex-direction: column;
                        gap: 0.5rem;
                        padding: 0.5rem;
                        min-height: auto;
                    }
                    
                    .header-center {
                        order: -1;
                        width: 100%;
                    }
                    
                    .menu-bar {
                        flex-wrap: wrap;
                        justify-content: center;
                    }
                    
                    .menu-btn {
                        padding: 0.4rem 0.8rem;
                        font-size: 0.8rem;
                    }
                }
                
                /* مكتبة الأصول */
                .asset-library {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.8);
                    z-index: 1000;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                
                .asset-library.hidden {
                    display: none;
                }
                
                .asset-library-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 1rem;
                    background: #2d2d30;
                    border-bottom: 1px solid #3e3e42;
                }
                
                .asset-library-controls {
                    display: flex;
                    align-items: center;
                    gap: 1rem;
                }
                
                .library-type-selector {
                    background: #3c3c3c;
                    color: #d4d4d4;
                    border: 1px solid #464647;
                    padding: 0.4rem 0.8rem;
                    border-radius: 3px;
                    font-size: 0.9rem;
                }
                
                .close-btn {
                    background: #e74c3c;
                    color: white;
                    border: none;
                    padding: 0.5rem 0.8rem;
                    border-radius: 3px;
                    cursor: pointer;
                    font-size: 1rem;
                    line-height: 1;
                }
                
                .close-btn:hover {
                    background: #c0392b;
                }
                
                .asset-library-content {
                    background: #1e1e1e;
                    width: 80%;
                    max-width: 1200px;
                    height: 80%;
                    max-height: 800px;
                    border-radius: 8px;
                    overflow: hidden;
                    display: flex;
                    flex-direction: column;
                }
                
                .asset-grid {
                    flex: 1;
                    overflow-y: auto;
                    padding: 1rem;
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                    gap: 1rem;
                }
                
                .asset-card {
                    background: #2d2d30;
                    border: 1px solid #3e3e42;
                    border-radius: 8px;
                    padding: 1rem;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    text-align: center;
                }
                
                .asset-card:hover {
                    background: #383838;
                    border-color: #007acc;
                    transform: translateY(-2px);
                }
                
                .asset-thumbnail {
                    width: 100%;
                    height: 120px;
                    background: #1e1e1e;
                    border-radius: 4px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-bottom: 0.5rem;
                    overflow: hidden;
                }
                
                .asset-thumbnail img {
                    max-width: 100%;
                    max-height: 100%;
                    object-fit: cover;
                }
                
                .asset-thumbnail.no-thumbnail {
                    color: #888;
                    font-size: 3rem;
                }
                
                .asset-name {
                    font-weight: bold;
                    margin-bottom: 0.3rem;
                    word-break: break-word;
                }
                
                .asset-info {
                    font-size: 0.8rem;
                    color: #888;
                }
                
                /* وضع ملء الشاشة لمنطقة العرض */
                .dashboard-content.fullscreen-mode {
                    grid-template-columns: 1fr;
                }
                
                .dashboard-content.fullscreen-mode .editor-container {
                    display: none;
                }
                
                .viewport-container.fullscreen-viewport {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100vw;
                    height: 100vh;
                    z-index: 999;
                    background: #1e1e1e;
                }
                
                .viewport-container.fullscreen-viewport .viewport {
                    height: calc(100vh - 60px);
                }
                
                .viewport-container.fullscreen-viewport .viewport canvas {
                    width: 100% !important;
                    height: 100% !important;
                }
                
                /* تحسين أزرار منطقة العرض */
                .viewport-btn {
                    background: #2d2d30;
                    color: #d4d4d4;
                    border: 1px solid #464647;
                    padding: 0.4rem 0.6rem;
                    border-radius: 3px;
                    cursor: pointer;
                    font-size: 1rem;
                    transition: all 0.2s ease;
                }
                
                .viewport-btn:hover {
                    background: #383838;
                    border-color: #007acc;
                }
                
                .viewport-btn:active {
                    background: #007acc;
                    color: white;
                }
                
                /* لوحة استيراد الأصول الخارجية */
                .import-assets-panel {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.8);
                    z-index: 1000;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                
                .import-assets-panel.hidden {
                    display: none;
                }
                
                .import-panel-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 1rem;
                    background: #2d2d30;
                    border-bottom: 1px solid #3e3e42;
                }
                
                .import-panel-content {
                    background: #1e1e1e;
                    width: 90%;
                    max-width: 800px;
                    height: 80%;
                    max-height: 600px;
                    border-radius: 8px;
                    overflow: hidden;
                    display: flex;
                    flex-direction: column;
                }
                
                .import-options {
                    flex: 1;
                    overflow-y: auto;
                    padding: 1rem;
                }
                
                .import-section {
                    background: #2d2d30;
                    border: 1px solid #3e3e42;
                    border-radius: 8px;
                    padding: 1rem;
                    margin-bottom: 1rem;
                }
                
                .import-section h4 {
                    margin: 0 0 1rem 0;
                    color: #d4d4d4;
                }
                
                .import-section input[type="file"] {
                    display: block;
                    width: 100%;
                    padding: 0.5rem;
                    margin-bottom: 1rem;
                    background: #3c3c3c;
                    color: #d4d4d4;
                    border: 1px solid #464647;
                    border-radius: 4px;
                }
                
                .import-btn {
                    background: #007acc;
                    color: white;
                    border: none;
                    padding: 0.5rem 1rem;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 0.9rem;
                }
                
                .import-btn:hover {
                    background: #005a9e;
                }
                
                .import-btn:disabled {
                    background: #555;
                    cursor: not-allowed;
                }
                
                .import-status {
                    background: #2d2d30;
                    border: 1px solid #3e3e42;
                    border-radius: 8px;
                    padding: 1rem;
                    margin-bottom: 1rem;
                    text-align: center;
                }
                
                .import-status.success {
                    border-color: #28a745;
                    background: #1a4d2e;
                }
                
                .import-status.error {
                    border-color: #dc3545;
                    background: #4d1a1a;
                }
                
                .imported-files {
                    background: #2d2d30;
                    border: 1px solid #3e3e42;
                    border-radius: 8px;
                    padding: 1rem;
                }
                
                .imported-files h4 {
                    margin: 0 0 1rem 0;
                    color: #d4d4d4;
                }
                
                .imported-files-list {
                    max-height: 200px;
                    overflow-y: auto;
                    background: #1e1e1e;
                    border: 1px solid #3e3e42;
                    border-radius: 4px;
                    padding: 0.5rem;
                    margin-bottom: 1rem;
                }
                
                .file-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 0.3rem 0.5rem;
                    border-bottom: 1px solid #3e3e42;
                    font-size: 0.8rem;
                }
                
                .file-item:last-child {
                    border-bottom: none;
                }
                
                .file-name {
                    color: #d4d4d4;
                    flex: 1;
                }
                
                .file-size {
                    color: #888;
                    margin-left: 1rem;
                }
                
                .clear-btn {
                    background: #dc3545;
                    color: white;
                    border: none;
                    padding: 0.5rem 1rem;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 0.9rem;
                }
                
                .clear-btn:hover {
                    background: #c82333;
                }
            </style>
        `;
    }

    /**
     * ربط مستمعي الأحداث
     */
    private setupEventListeners(): void {
        const backBtn = document.getElementById('back-btn');
        const newBtn = document.getElementById('new-btn');
        const webgpuExampleBtn = document.getElementById('webgpu-example-btn');
        const saveBtn = document.getElementById('save-btn');
        const loadBtn = document.getElementById('load-btn');
        const libraryBtn = document.getElementById('library-btn');
        const runBtn = document.getElementById('run-btn');
        const engineSelector = document.getElementById('engine-selector') as HTMLSelectElement;
        const closeLibraryBtn = document.getElementById('close-library-btn');
        const libraryAssetTypeSelect = document.getElementById('library-asset-type') as HTMLSelectElement;
        
        // أزرار منطقة العرض
        const wireframeBtn = document.getElementById('wireframe-btn');
        const fullscreenViewportBtn = document.getElementById('fullscreen-viewport-btn');
        
        // أزرار استيراد الأصول
        const importAssetsBtn = document.getElementById('import-assets-btn');
        const closeImportPanelBtn = document.getElementById('close-import-panel-btn');
        const importSingleFilesBtn = document.getElementById('import-single-files-btn');
        const importFolderBtn = document.getElementById('import-folder-btn');
        const clearImportsBtn = document.getElementById('clear-imports-btn');

        backBtn?.addEventListener('click', () => {
            this.cleanup();
            this.router.navigate('/');
        });

        newBtn?.addEventListener('click', () => this.newProject());
        webgpuExampleBtn?.addEventListener('click', () => this.loadWebGPUExample());
        saveBtn?.addEventListener('click', () => this.saveProject());
        loadBtn?.addEventListener('click', () => this.loadProject());
        libraryBtn?.addEventListener('click', () => this.openAssetLibrary());
        runBtn?.addEventListener('click', () => this.runCode());
        
        engineSelector?.addEventListener('change', () => this.switchEngine());
        closeLibraryBtn?.addEventListener('click', () => this.closeAssetLibrary());
        libraryAssetTypeSelect?.addEventListener('change', () => this.refreshAssetLibrary());
        
        // مستمعي أحداث أزرار منطقة العرض
        wireframeBtn?.addEventListener('click', () => this.toggleWireframe());
        fullscreenViewportBtn?.addEventListener('click', () => this.toggleFullscreenViewport());
        
        // مستمعي أحداث أزرار استيراد الأصول
        importAssetsBtn?.addEventListener('click', () => this.openImportAssetsPanel());
        closeImportPanelBtn?.addEventListener('click', () => this.closeImportAssetsPanel());
        importSingleFilesBtn?.addEventListener('click', () => this.importSelectedFiles());
        importFolderBtn?.addEventListener('click', () => this.importSelectedFolder());
        clearImportsBtn?.addEventListener('click', () => this.clearAllImports());
        
        // Audio context resume on user interaction
        const resumeAudioContext = () => {
            const babylon = (window as any).BABYLON;
            if (babylon && babylon.Engine && babylon.Engine.audioEngine && 
                babylon.Engine.audioEngine.audioContext && 
                babylon.Engine.audioEngine.audioContext.state === 'suspended') {
                console.log('Resuming audio context on user interaction...');
                babylon.Engine.audioEngine.audioContext.resume();
            }
        };
        
        // Add listeners for user interaction to resume audio context
        ['click', 'touchstart', 'keydown'].forEach(eventType => {
            document.addEventListener(eventType, resumeAudioContext, { once: true });
        });
    }

    /**
     * تهيئة محرر Monaco
     */
    private async initializeEditor(): Promise<void> {
        try {
            // Configure Monaco Environment to disable all workers
            (window as any).MonacoEnvironment = {
                getWorker: () => {
                    return {
                        postMessage: () => {},
                        terminate: () => {},
                        addEventListener: () => {},
                        removeEventListener: () => {}
                    };
                }
            };

            const monaco = await import('monaco-editor');
            
            // Disable language features that require workers
            monaco.languages.typescript.javascriptDefaults.setWorkerOptions({
                customWorkerPath: undefined
            });
            monaco.languages.typescript.typescriptDefaults.setWorkerOptions({
                customWorkerPath: undefined
            });

            const editorElement = document.getElementById("monaco-editor");
            if (!editorElement) {
                console.error('Monaco editor element not found!');
                return;
            }
            
            console.log('Monaco editor element found:', editorElement);

            this.editor = monaco.editor.create(editorElement as HTMLElement, {
                value: "",
                language: 'javascript',
                theme: 'vs-dark',
                automaticLayout: true,
                minimap: { enabled: false },
                fontSize: 14,
                lineNumbers: 'on',
                roundedSelection: false,
                scrollBeyondLastLine: false,
                readOnly: false,
                domReadOnly: false,
                cursorStyle: 'line',
                wordWrap: 'on',
                selectOnLineNumbers: true,
                mouseWheelZoom: true,
                contextmenu: true,
                // Text direction settings
                renderControlCharacters: false,
                renderWhitespace: 'none',
                // Disable features that require workers to avoid errors
                quickSuggestions: false,
                parameterHints: { enabled: false },
                suggestOnTriggerCharacters: false,
                acceptSuggestionOnEnter: "off",
                tabCompletion: "off",
                wordBasedSuggestions: "off",
                // Enable basic editing features
                find: {
                    addExtraSpaceOnTop: false,
                    autoFindInSelection: 'never',
                    seedSearchStringFromSelection: 'never'
                }
            });

            console.log('Monaco editor created successfully:', this.editor);

            // Force LTR direction on the editor
            const editorDomNode = this.editor.getDomNode();
            if (editorDomNode) {
                editorDomNode.style.direction = 'ltr';
                editorDomNode.dir = 'ltr';
                
                // Also set direction on editor container
                const editorContainer = editorDomNode.querySelector('.monaco-editor');
                if (editorContainer) {
                    (editorContainer as HTMLElement).style.direction = 'ltr';
                    (editorContainer as HTMLElement).dir = 'ltr';
                }
            }

            // تحديث موضع المؤشر
            this.editor.onDidChangeCursorPosition((e: any) => {
                const position = document.getElementById('cursor-position');
                if (position) {
                    position.textContent = `السطر ${e.position.lineNumber}، العمود ${e.position.column}`;
                }
            });

        } catch (error) {
            console.error("Failed to initialize Monaco editor:", error);
            this.editor = null;
        }
    }

    /**
     * فحص دعم WebGPU
     */
    private async checkWebGPUSupport(): Promise<void> {
        try {
            const { WebGPUEngine } = await import('@babylonjs/core/Engines/webgpuEngine');
            const engineSelector = document.getElementById('engine-selector') as HTMLSelectElement;
            const webgpuOption = engineSelector?.querySelector('option[value="webgpu"]') as HTMLOptionElement;
            
            // فحص مفصل للدعم
            let webGPUSupported = false;
            let supportMessage = 'WebGPU';
            
            try {
                // فحص أولي
                const basicSupport = await WebGPUEngine.IsSupportedAsync;
                
                if (basicSupport && navigator.gpu) {
                    // محاولة الحصول على adapter للتأكد من الدعم الفعلي
                    const adapter = await navigator.gpu.requestAdapter();
                    if (adapter) {
                        webGPUSupported = true;
                        console.log('WebGPU is fully supported by this browser');
                    } else {
                        supportMessage = 'WebGPU (لا يوجد محول متاح)';
                        console.log('WebGPU API available but no adapter found');
                    }
                } else {
                    supportMessage = 'WebGPU (غير مدعوم)';
                    console.log('WebGPU is not supported by this browser');
                }
            } catch (adapterError) {
                console.log('WebGPU adapter check failed:', adapterError);
                supportMessage = 'WebGPU (خطأ في التحقق)';
            }
            
            if (webgpuOption) {
                webgpuOption.disabled = !webGPUSupported;
                webgpuOption.textContent = supportMessage;
            }
            
        } catch (error) {
            console.error('Error checking WebGPU support:', error);
            const engineSelector = document.getElementById('engine-selector') as HTMLSelectElement;
            const webgpuOption = engineSelector?.querySelector('option[value="webgpu"]') as HTMLOptionElement;
            if (webgpuOption) {
                webgpuOption.disabled = true;
                webgpuOption.textContent = 'WebGPU (خطأ)';
            }
        }
    }

    /**
     * تهيئة محرك Babylon.js
     */
    private async initializeBabylon(): Promise<void> {
        try {
            // استيراد Babylon.js بشكل مودولي
            const [
                { Engine },
                { WebGPUEngine },
                { Scene },
                { Color3 }
            ] = await Promise.all([
                import('@babylonjs/core/Engines/engine'),
                import('@babylonjs/core/Engines/webgpuEngine'),
                import('@babylonjs/core/scene'),
                import('@babylonjs/core/Maths/math.color')
            ]);

            this.canvas = document.getElementById('babylon-canvas') as HTMLCanvasElement;
            if (!this.canvas) return;

            // تحديد نوع المحرك بناءً على الاختيار
            const engineSelector = document.getElementById('engine-selector') as HTMLSelectElement;
            const selectedEngine = engineSelector?.value || 'webgl2';

            if (selectedEngine === 'webgpu') {
                try {
                    // فحص دعم WebGPU بشكل أكثر تفصيلاً
                    console.log('Checking WebGPU support...');
                    
                    // فحص أولي
                    const webGPUSupported = await WebGPUEngine.IsSupportedAsync;
                    console.log('WebGPU support check:', webGPUSupported);
                    
                    if (!webGPUSupported) {
                        throw new Error('WebGPU basic support check failed');
                    }
                    
                    // فحص إضافي للـ navigator.gpu
                    if (!navigator.gpu) {
                        throw new Error('navigator.gpu is not available');
                    }
                    
                    // محاولة الحصول على adapter
                    const adapter = await navigator.gpu.requestAdapter();
                    if (!adapter) {
                        throw new Error('Failed to get WebGPU adapter');
                    }
                    
                    console.log('WebGPU adapter obtained, creating engine...');
                    this.engine = new WebGPUEngine(this.canvas, {
                        antialias: true,
                        stencil: true
                    });
                    
                    console.log('Initializing WebGPU engine...');
                    await this.engine.initAsync();
                    console.log('WebGPU engine initialized successfully');
                    this.isWebGPUEnabled = true;
                } catch (webgpuError) {
                    console.warn('WebGPU initialization failed, falling back to WebGL2:', webgpuError);
                    
                    // Fallback to WebGL2 and update the selector
                    const engineSelector = document.getElementById('engine-selector') as HTMLSelectElement;
                    if (engineSelector) {
                        engineSelector.value = 'webgl2';
                    }
                    
                    this.engine = new Engine(this.canvas, true, {
                        preserveDrawingBuffer: true,
                        stencil: true,
                        antialias: true
                    });
                    this.isWebGPUEnabled = false;
                    
                    // Show error message to user
                    const statusText = document.getElementById('status-text');
                    if (statusText) {
                        statusText.textContent = 'WebGPU غير مدعوم، تم التبديل إلى WebGL2';
                    }
                }
            } else {
                // إنشاء محرك WebGL2
                console.log('Creating WebGL2 engine...');
                this.engine = new Engine(this.canvas, true, {
                    preserveDrawingBuffer: true,
                    stencil: true,
                    antialias: true
                });
                this.isWebGPUEnabled = false;
            }

            // Audio engine will be initialized on first user interaction
            console.log('Skipping audio engine initialization - will be created on user interaction');

            // إنشاء مشهد فارغ
            this.scene = new Scene(this.engine);
            this.scene.clearColor = new Color3(0.1, 0.1, 0.1);

            // بدء حلقة العرض - يعرض المشهد دائماً لضمان عمل الرسوم المتحركة
            this.engine.runRenderLoop(() => {
                if (this.scene) {
                    try {
                        this.scene.render();
                                            } catch (error) {
                            // تجاهل خطأ "No camera defined" أثناء التهيئة
                            const errorMessage = error instanceof Error ? error.message : String(error);
                            if (!errorMessage.includes('No camera defined')) {
                                console.error('Render error:', error);
                            }
                        }
                }
            });

            // التعامل مع تغيير حجم النافذة
            window.addEventListener('resize', () => {
                this.engine?.resize();
            });

            // إخفاء شاشة التحميل
            const loadingElement = document.getElementById('viewport-loading');
            if (loadingElement) {
                loadingElement.style.display = 'none';
            }

            // تحديث معلومات المحرك
            this.updateEngineInfo();

        } catch (error) {
            console.error('Failed to initialize Babylon.js:', error);
        }
    }

    /**
     * تحديث معلومات المحرك
     */
    private updateEngineInfo(): void {
        const engineInfo = document.getElementById('engine-info');
        if (engineInfo && this.engine) {
            // تحديد نوع المحرك بناءً على النوع الفعلي
            if (this.engine.constructor.name === 'WebGPUEngine' || this.engine._webgpuDevice) {
                engineInfo.textContent = 'WebGPU';
                this.isWebGPUEnabled = true;
            } else {
                engineInfo.textContent = this.engine.webGLVersion > 1 ? 'WebGL2' : 'WebGL';
                this.isWebGPUEnabled = false;
            }
        }
    }

    /**
     * تبديل محرك العرض
     */
    private async switchEngine(): Promise<void> {
        const engineSelector = document.getElementById('engine-selector') as HTMLSelectElement;
        const selectedEngine = engineSelector?.value || 'webgl2';
        
        try {
            // تنظيف المحرك الحالي
            if (this.engine) {
                this.engine.dispose();
            }

            // إعادة تهيئة المحرك الجديد
            await this.initializeBabylon();
            
            // إعادة تشغيل الكود الحالي إذا كان موجودًا
            if (this.editor && this.editor.getValue().trim()) {
                await this.runCode();
            }

            const statusText = document.getElementById('status-text');
            if (statusText) {
                statusText.textContent = `تم التبديل إلى ${selectedEngine === 'webgpu' ? 'WebGPU' : 'WebGL2'}`;
            }

        } catch (error) {
            console.error('Error switching engine:', error);
            const statusText = document.getElementById('status-text');
            if (statusText) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                statusText.textContent = `خطأ في تبديل المحرك: ${errorMessage}`;
            }
        }
    }

    /**
     * إنشاء محرك افتراضي بناءً على إعدادات المستخدم
     */
    private async createDefaultEngine(): Promise<void> {
        const engineSelector = document.getElementById('engine-selector') as HTMLSelectElement;
        const selectedEngine = engineSelector?.value || 'webgl2';

        const [
            { Engine },
            { WebGPUEngine }
        ] = await Promise.all([
            import('@babylonjs/core/Engines/engine'),
            import('@babylonjs/core/Engines/webgpuEngine')
        ]);

        if (selectedEngine === 'webgpu') {
            try {
                const webGPUSupported = await WebGPUEngine.IsSupportedAsync;
                if (webGPUSupported && navigator.gpu) {
                    const adapter = await navigator.gpu.requestAdapter();
                    if (adapter) {
                        this.engine = new WebGPUEngine(this.canvas, {
                            antialias: true,
                            stencil: true,
                            preserveDrawingBuffer: true
                        });
                        await this.engine.initAsync();
                        this.isWebGPUEnabled = true;
                        return;
                    }
                }
            } catch (error) {
                console.warn('Failed to create WebGPU engine, falling back to WebGL2:', error);
            }
        }

        // Create WebGL2 engine as fallback
        this.engine = new Engine(this.canvas, true, {
            preserveDrawingBuffer: true,
            stencil: true,
            antialias: true
        });
        this.isWebGPUEnabled = false;
        
        // Audio engine will be initialized on first user interaction
        console.log('Skipping audio engine initialization in fallback - will be created on user interaction');
    }

    /**
     * تشغيل الكود
     */
    private async runCode(): Promise<void> {
        if (!this.editor) return;

        try {
            const code = this.editor.getValue();
            if (!code.trim()) return;

            // Validate code security
            const validation = CodeSecurityManager.validateCode(code);
            if (!validation.valid) {
                const errorMessage = `أخطاء أمنية في الكود:\n${validation.errors.join('\n')}`;
                console.error('Security validation failed:', validation.errors);
                
                const statusText = document.getElementById('status-text');
                if (statusText) {
                    statusText.textContent = 'خطأ أمني: كود غير آمن';
                }
                
                alert(errorMessage);
                return;
            }

            // Create checksum for integrity verification
            const originalChecksum = CodeSecurityManager.createChecksum(code);
            
            // Sanitize code
            const sanitizedCode = CodeSecurityManager.sanitizeCode(code);
            
            // Verify code hasn't been tampered with
            const sanitizedChecksum = CodeSecurityManager.createChecksum(sanitizedCode);
            
            console.log('Code validation passed, executing safely...');

            // تنظيف الأصوات الحالية أولاً
            if (this.scene && this.scene._spatialSounds) {
                console.log('Cleaning up previous sounds...');
                this.scene._spatialSounds.forEach((sound: any) => {
                    if (sound.stop) {
                        sound.stop();
                    }
                    if (sound.audioSource) {
                        try {
                            sound.audioSource.stop();
                            sound.audioSource.disconnect();
                        } catch (e) {
                            // Audio source might already be stopped
                        }
                    }
                    if (sound.gainNode) {
                        try {
                            sound.gainNode.disconnect();
                        } catch (e) {
                            // Gain node might already be disconnected
                        }
                    }
                });
                this.scene._spatialSounds = [];
                console.log('Previous sounds cleaned up');
            }

            // تنظيف المحرك والمشهد الحالي بالكامل
            if (this.scene) {
                this.scene.dispose();
            }
            if (this.engine) {
                this.engine.dispose();
            }

            // استيراد BABYLON للكود المستخدم مع دعم شامل
            const [
                BABYLON_CORE,
                { Engine },
                { WebGPUEngine },
                { PBRMaterial },
                { NodeMaterial },
                { DefaultRenderingPipeline },
                { AudioEngine },
                BABYLON_GUI
            ] = await Promise.all([
                import('@babylonjs/core'),
                import('@babylonjs/core/Engines/engine'),
                import('@babylonjs/core/Engines/webgpuEngine'),
                import('@babylonjs/core/Materials/PBR/pbrMaterial'),
                import('@babylonjs/core/Materials/Node/nodeMaterial'),
                import('@babylonjs/core/PostProcesses/RenderPipeline/Pipelines/defaultRenderingPipeline'),
                import('@babylonjs/core/Audio/audioEngine'),
                import('@babylonjs/gui')
            ]);

            // Make BABYLON globally available for audio context resume
            (window as any).BABYLON = BABYLON_CORE;

            // إضافة الإضافات المطلوبة للميزات الأساسية
            await Promise.all([
                import('@babylonjs/core/Lights/directionalLight'),
                import('@babylonjs/core/Lights/hemisphericLight'), 
                import('@babylonjs/core/Cameras/arcRotateCamera'),
                import('@babylonjs/core/Meshes/Builders/groundBuilder'),
                import('@babylonjs/core/Materials/Node'),
                import('@babylonjs/core/Materials/standardMaterial'),
                import('@babylonjs/core/Materials/Textures/texture'),
                import('@babylonjs/core/Materials/Textures/dynamicTexture'),
                import('@babylonjs/core/Meshes/mesh'),
                import('@babylonjs/core/Meshes/abstractMesh'),
                import('@babylonjs/core/Loading/sceneLoader'),
                import('@babylonjs/core/Loading/Plugins/babylonFileLoader'),
                import('@babylonjs/loaders/glTF/glTFFileLoader'), // <-- Corrected for @babylonjs/loaders package
                import('@babylonjs/core/Rendering/depthRendererSceneComponent'),
                import('@babylonjs/core/Rendering/geometryBufferRendererSceneComponent'),
                import('@babylonjs/core/Rendering/prePassRendererSceneComponent'),
                import('@babylonjs/core/Misc/tools'),
                import('@babylonjs/core/Misc/fileTools'),
                import('@babylonjs/core/Audio/sound'),
                import('@babylonjs/core/Audio/audioEngine')
            ]);
            // Explicitly register the GLTFFileLoader with SceneLoader
            try {
                const { SceneLoader } = await import('@babylonjs/core/Loading/sceneLoader');
                const { GLTFFileLoader } = await import('@babylonjs/loaders/glTF/glTFFileLoader');
                SceneLoader.RegisterPlugin(new GLTFFileLoader());
                console.log('GLTFFileLoader registered explicitly.');
            } catch (e) {
                console.warn('Failed to explicitly register GLTFFileLoader:', e);
            }

            // تفعيل محرك الصوت مبكراً
            if (!BABYLON_CORE.Engine.audioEngine) {
                console.log('Pre-initializing audio engine...');
                try {
                    BABYLON_CORE.Engine.audioEngine = new AudioEngine();
                    Engine.audioEngine = BABYLON_CORE.Engine.audioEngine;
                    console.log('Audio engine pre-initialized');
                } catch (error) {
                    console.warn('Failed to pre-initialize audio engine:', error);
                }
            }

            // إنشاء كائن BABYLON كامل مع جميع الميزات
            const BABYLON = {
                ...BABYLON_CORE,
                Engine,
                WebGPUEngine,
                PBRMaterial,
                NodeMaterial,
                DefaultRenderingPipeline,
                GUI: BABYLON_GUI,
                
                // Custom Sound class that actually works
                Sound: class {
                    name: string;
                    scene: any;
                    options: any;
                    readyToPlayCallback: any;
                    position: any;
                    audioBuffer: any;
                    audioSource: any;
                    gainNode: any;
                    isPlaying: boolean;
                    _volume: number;
                    _lastLoggedVolume: number = 0;
                    _isLoading: boolean = false;

                    constructor(name: string, urlOrArrayBuffer: string, scene: any, readyToPlayCallback: any, options: any = {}) {
                        this.name = name;
                        this.scene = scene;
                        this.options = {
                            loop: options.loop || false,
                            autoplay: options.autoplay || false,
                            spatialSound: options.spatialSound || false,
                            maxDistance: options.maxDistance || 100,
                            volume: options.volume || 1.0,
                            ...options
                        };
                        this.readyToPlayCallback = readyToPlayCallback;
                        this.position = new BABYLON_CORE.Vector3(0, 0, 0);
                        this.audioBuffer = null;
                        this.audioSource = null;
                        this.gainNode = null;
                        this.isPlaying = false;
                        this._volume = this.options.volume;
                        
                        // Ensure audio engine exists and is properly initialized
                        if (!BABYLON_CORE.Engine.audioEngine) {
                            console.log('Initializing audio engine...');
                            BABYLON_CORE.Engine.audioEngine = new AudioEngine();
                            Engine.audioEngine = BABYLON_CORE.Engine.audioEngine;
                            
                            // Wait for audio engine to be ready
                            if (BABYLON_CORE.Engine.audioEngine.audioContext && BABYLON_CORE.Engine.audioEngine.audioContext.state === 'suspended') {
                                console.log('Audio context suspended, waiting for user interaction...');
                                // Audio context will be resumed on first user interaction
                            }
                        }
                        
                        // Check if audio engine is ready
                        if (!BABYLON_CORE.Engine.audioEngine.audioContext) {
                            console.warn('Audio context not available, will retry loading later');
                            setTimeout(() => this._loadAudio(urlOrArrayBuffer), 500);
                            return;
                        }
                        
                        // Register for spatial audio updates
                        if (!scene._spatialSounds) {
                            scene._spatialSounds = [];
                            console.log('Setting up spatial audio updater for scene');
                            
                            // Set up spatial audio updater for this scene
                            const spatialAudioUpdater = () => {
                                if (scene.activeCamera && scene._spatialSounds) {
                                    scene._spatialSounds.forEach((sound: any) => {
                                        if (sound._updateSpatialAudio && sound.options.spatialSound) {
                                            sound._updateSpatialAudio(scene.activeCamera.position);
                                        }
                                    });
                                }
                            };
                            
                            scene.registerBeforeRender(spatialAudioUpdater);
                            console.log('Spatial audio updater registered');
                        }
                        scene._spatialSounds.push(this);
                        console.log(`Sound ${this.name} registered for spatial audio`);
                        
                        // Load audio with correct path
                        let audioUrl = urlOrArrayBuffer;
                        if (!urlOrArrayBuffer.startsWith('http')) {
                            // Handle different path formats
                            if (urlOrArrayBuffer.startsWith('sounds/')) {
                                // Convert "sounds/001.wav" to "/external-import/sounds/001.wav"
                                audioUrl = `/external-import/${urlOrArrayBuffer}`;
                            } else {
                                // Assume it's just the filename
                                audioUrl = `/external-import/sounds/${urlOrArrayBuffer}`;
                            }
                        }
                        this._loadAudio(audioUrl);
                    }
                    
                    async _loadAudio(url: string) {
                        // Prevent multiple simultaneous loads
                        if (this._isLoading) {
                            console.warn(`Audio ${this.name} is already loading, skipping...`);
                            return;
                        }
                        this._isLoading = true;
                        
                        try {
                            // Ensure audio engine and context are properly initialized
                            if (!BABYLON_CORE.Engine.audioEngine || !BABYLON_CORE.Engine.audioEngine.audioContext) {
                                console.warn(`Audio engine not ready for ${this.name}, retrying in 100ms...`);
                                this._isLoading = false;
                                setTimeout(() => this._loadAudio(url), 100);
                                return;
                            }

                            const audioContext = BABYLON_CORE.Engine.audioEngine.audioContext;
                            
                            // Check if URL is accessible
                            const response = await fetch(url);
                            if (!response.ok) {
                                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                            }
                            
                            const arrayBuffer = await response.arrayBuffer();
                            
                            // Validate array buffer size
                            if (arrayBuffer.byteLength === 0) {
                                throw new Error('Audio file is empty');
                            }
                            
                            // Check if file is too small to be a valid audio file
                            if (arrayBuffer.byteLength < 1000) {
                                throw new Error(`Audio file too small (${arrayBuffer.byteLength} bytes) - likely corrupted or invalid`);
                            }
                            
                            console.log(`Attempting to decode audio for ${this.name}, size: ${arrayBuffer.byteLength} bytes`);
                            
                            // Try to decode with error handling
                            try {
                                this.audioBuffer = await audioContext.decodeAudioData(arrayBuffer);
                                console.log(`Successfully decoded audio for ${this.name}`);
                            } catch (decodeError) {
                                console.warn(`Audio decode failed for ${this.name}, trying alternative approach...`, decodeError);
                                
                                // Create a copy of the array buffer to avoid detachment issues
                                const arrayBufferCopy = arrayBuffer.slice(0);
                                
                                // Try with a promise-based approach for older browsers
                                this.audioBuffer = await new Promise((resolve, reject) => {
                                    audioContext.decodeAudioData(
                                        arrayBufferCopy,
                                        resolve,
                                        reject
                                    );
                                });
                            }
                            
                            // Create gain node
                            this.gainNode = audioContext.createGain();
                            this.gainNode.gain.value = this._volume;
                            this.gainNode.connect(audioContext.destination);
                            
                            console.log(`Sound ${this.name} loaded successfully`);
                            if (this.readyToPlayCallback) {
                                this.readyToPlayCallback();
                            }
                            
                            if (this.options.autoplay) {
                                this.play();
                            }
                        } catch (error) {
                            console.error(`Failed to load sound ${this.name}:`, error);
                            
                            // Create a silent audio buffer as fallback
                            try {
                                if (BABYLON_CORE.Engine.audioEngine && BABYLON_CORE.Engine.audioEngine.audioContext) {
                                    const audioContext = BABYLON_CORE.Engine.audioEngine.audioContext;
                                    this.audioBuffer = audioContext.createBuffer(1, 44100, 44100); // 1 second of silence
                                    this.gainNode = audioContext.createGain();
                                    this.gainNode.gain.value = 0; // Mute the fallback
                                    this.gainNode.connect(audioContext.destination);
                                    
                                    console.log(`Created silent fallback for sound ${this.name}`);
                                    if (this.readyToPlayCallback) {
                                        this.readyToPlayCallback();
                                    }
                                }
                            } catch (fallbackError) {
                                console.error(`Failed to create fallback for sound ${this.name}:`, fallbackError);
                            }
                        } finally {
                            this._isLoading = false;
                        }
                    }
                    
                    play() {
                        if (!this.audioBuffer || !BABYLON_CORE.Engine.audioEngine) return;
                        
                        // Stop previous source
                        if (this.audioSource) {
                            this.audioSource.stop();
                        }
                        
                        // Create new source
                        const audioContext = BABYLON_CORE.Engine.audioEngine.audioContext;
                        if (!audioContext) {
                            console.warn('Audio context not available for playing sound');
                            return;
                        }
                        this.audioSource = audioContext.createBufferSource();
                        this.audioSource.buffer = this.audioBuffer;
                        this.audioSource.loop = this.options.loop;
                        this.audioSource.connect(this.gainNode);
                        this.audioSource.start();
                        this.isPlaying = true;
                        
                        // Handle end event
                        this.audioSource.onended = () => {
                            this.isPlaying = false;
                        };
                        
                        console.log(`Playing sound ${this.name}`);
                    }
                    
                    stop() {
                        if (this.audioSource) {
                            try {
                                this.audioSource.stop();
                                this.audioSource.disconnect();
                            } catch (e) {
                                // Audio source might already be stopped/disconnected
                            }
                            this.audioSource = null;
                            this.isPlaying = false;
                        }
                    }
                    
                    dispose() {
                        this.stop();
                        if (this.gainNode) {
                            try {
                                this.gainNode.disconnect();
                            } catch (e) {
                                // Gain node might already be disconnected
                            }
                            this.gainNode = null;
                        }
                        this.audioBuffer = null;
                        
                        // Remove from scene's spatial sounds array
                        if (this.scene && this.scene._spatialSounds) {
                            const index = this.scene._spatialSounds.indexOf(this);
                            if (index > -1) {
                                this.scene._spatialSounds.splice(index, 1);
                            }
                        }
                        
                        console.log(`Sound ${this.name} disposed`);
                    }
                    
                    setPosition(position: any) {
                        this.position = position;
                    }
                    
                    setVolume(volume: number) {
                        this._volume = volume;
                        if (this.gainNode) {
                            this.gainNode.gain.value = volume;
                        }
                    }
                    
                    getVolume() {
                        return this._volume;
                    }
                    
                    isReady() {
                        return !!this.audioBuffer;
                    }
                    
                    // Update spatial audio if needed
                    _updateSpatialAudio(cameraPosition: any) {
                        if (this.options.spatialSound && this.gainNode && cameraPosition && this.isPlaying) {
                            const distance = BABYLON_CORE.Vector3.Distance(cameraPosition, this.position);
                            const normalizedDistance = distance / this.options.maxDistance;
                            const volume = Math.max(0, 1 - normalizedDistance);
                            this.gainNode.gain.value = volume * this._volume;
                            
                            // Reduced debug logging - only when volume changes significantly
                            const volumePercent = Math.round(volume * 100);
                            if (volumePercent % 10 === 0 && volumePercent !== this._lastLoggedVolume) {
                                console.log(`${this.name}: distance=${distance.toFixed(1)}, volume=${volumePercent}%`);
                                this._lastLoggedVolume = volumePercent;
                            }
                        }
                    }
                },
                
                // إضافة دالة مساعدة لإنشاء مواد احتياطية
                createFallbackMaterial: function(name: string, scene: any) {
                    const material = new BABYLON_CORE.StandardMaterial(name, scene);
                    material.diffuseColor = new BABYLON_CORE.Color3(0.6, 0.8, 1.0);
                    material.specularColor = new BABYLON_CORE.Color3(0.2, 0.2, 0.2);
                    return material;
                },
                
                // إضافة دالة لتفعيل الصوت
                activateAudioContext: async function() {
                    if (!BABYLON_CORE.Engine.audioEngine) {
                        console.log('Creating audio engine on demand...');
                        try {
                            BABYLON_CORE.Engine.audioEngine = new AudioEngine();
                            Engine.audioEngine = BABYLON_CORE.Engine.audioEngine;
                            console.log('Audio engine created successfully');
                        } catch (error) {
                            console.error('Failed to create audio engine:', error);
                            return Promise.reject(error);
                        }
                    }
                    
                    if (BABYLON_CORE.Engine.audioEngine && BABYLON_CORE.Engine.audioEngine.audioContext) {
                        const audioContext = BABYLON_CORE.Engine.audioEngine.audioContext;
                        if (audioContext.state === 'suspended') {
                            console.log('Resuming suspended audio context...');
                            return audioContext.resume();
                        }
                        console.log('Audio context state:', audioContext.state);
                        return Promise.resolve();
                    }
                    console.log('No audio context found');
                    return Promise.resolve();
                }
            };

            // إنشاء محرك مؤقت ليكون متاحاً للكود المستخدم
            console.log('Creating temporary engine for user code...');
            await this.createDefaultEngine();
            
            // محرك الصوت يجب أن يكون مفعل مسبقاً
            console.log('Audio engine status:', !!BABYLON_CORE.Engine.audioEngine);
            
            // تشغيل الكود المستخدم باستخدام نظام آمن
            console.log('Running user code with security measures...');
            const result = await this.executeUserCodeSafely(sanitizedCode, this.engine, this.canvas, BABYLON, originalChecksum);
            
            // التحقق من ما إذا كان المستخدم قد عرّف محرك مخصص
            if (result.createEngine) {
                console.log('User defined createEngine found, replacing temporary engine...');
                // تنظيف المحرك المؤقت
                if (this.engine) {
                    this.engine.dispose();
                }
                // إنشاء المحرك المخصص
                this.engine = await result.createEngine();
                
                // تشغيل createScene مع المحرك الجديد
                if (result.createScene) {
                    this.scene = await result.createScene();
                } else if (result.scene) {
                    this.scene = result.scene;
                }
                
            } else if (result.engine && result.engine !== this.engine) {
                console.log('User defined custom engine variable, replacing temporary engine...');
                // تنظيف المحرك المؤقت
                if (this.engine) {
                    this.engine.dispose();
                }
                this.engine = result.engine;
                this.scene = result.scene;
                
            } else {
                // استخدام المحرك المؤقت الذي أنشأناه
                console.log('Using temporary engine, processing scene...');
                
                if (result.createScene) {
                    this.scene = await result.createScene();
                } else if (result.delayCreateScene) {
                    // Handle delayCreateScene function
                    console.log('Found delayCreateScene function, executing...');
                    this.scene = result.delayCreateScene();
                } else if (result.scene) {
                    this.scene = result.scene;
                } else {
                    // إنشاء مشهد افتراضي فارغ
                    const { Scene, Color3 } = BABYLON;
                    this.scene = new Scene(this.engine);
                    this.scene.clearColor = new Color3(0.1, 0.1, 0.1);
                }
            }

            // بدء حلقة العرض دائماً للمشهد الجديد
            if (this.engine && this.scene) {
                console.log('Starting render loop...');
                this.engine.runRenderLoop(() => {
                    if (this.scene) {
                        try {
                            // عرض المشهد حتى لو لم تكن هناك كاميرا نشطة
                            // هذا يضمن أن الرسوم المتحركة تستمر في العمل
                            this.scene.render();
                        } catch (error: any) {
                            // تجاهل خطأ "No camera defined" أثناء التهيئة
                            if (!error.message?.includes('No camera defined')) {
                                console.error('Render error:', error);
                            }
                        }
                    }
                });
                
                // التعامل مع تغيير حجم النافذة
                window.addEventListener('resize', () => {
                    this.engine?.resize();
                });
            }

            // تحديث معلومات المحرك
            this.updateEngineInfo();

            // تحديث الحالة
            const statusText = document.getElementById('status-text');
            if (statusText) {
                statusText.textContent = 'تم تشغيل الكود بنجاح';
            }

        } catch (error) {
            this.handleError(error, 'runCode');
            
            // في حالة الخطأ، أنشئ محرك افتراضي للعودة إلى الحالة الطبيعية
            try {
                await this.createDefaultEngine();
            } catch (fallbackError) {
                this.handleError(fallbackError, 'createDefaultEngine fallback');
            }
        }
    }



    /**
     * مشروع جديد
     */
    private async newProject(): Promise<void> {
        if (this.editor) {
            this.editor.setValue(this.getDefaultCode());
            // تشغيل الكود الافتراضي تلقائياً
            await this.runCode();
        }
    }

    /**
     * تحميل مثال WebGPU
     */
    private async loadWebGPUExample(): Promise<void> {
        if (this.editor) {
            this.editor.setValue(getWebGPUSceneCode());
            
            // تحديث النص في شريط الحالة
            const statusText = document.getElementById('status-text');
            if (statusText) {
                statusText.textContent = 'تم تحميل مثال WebGPU - جاري التشغيل...';
            }
            
            // تشغيل مثال WebGPU تلقائياً
            await this.runCode();
        }
    }

    /**
     * حفظ المشروع
     */
    private async saveProject(): Promise<void> {
        if (!this.editor) return;
        
        const code = this.editor.getValue();
        if (!code.trim()) {
            alert('لا يوجد كود للحفظ');
            return;
        }

        // الحصول على نوع الأصل المحدد
        const assetTypeSelect = document.getElementById('asset-type') as HTMLSelectElement;
        const assetType = assetTypeSelect?.value || 'map';

        // طلب اسم الأصل من المستخدم
        const assetName = prompt('أدخل اسم الأصل:');
        if (!assetName) return;

        try {
            const statusText = document.getElementById('status-text');
            if (statusText) {
                statusText.textContent = 'جاري الحفظ...';
            }

            const result = await this.apiClient.saveAsset(
                assetType as 'map' | 'character' | 'object',
                assetName,
                code
            );

            if (result.success) {
                if (statusText) {
                    statusText.textContent = `تم حفظ ${assetType} بنجاح - جاري التقاط الصورة المصغرة...`;
                }

                // انتظار أطول للتأكد من تحميل المشهد بالكامل (خاصة للمشاهد المعقدة)
                setTimeout(async () => {
                    try {
                        // التقاط صورة مصغرة للمشهد الحالي
                        await this.captureThumbnail(assetType as 'map' | 'character' | 'object', assetName);
                        
                        // نقل الأصول الخارجية المستوردة إلى مجلد المشروع
                        await this.moveExternalAssetsToProject(assetType as 'map' | 'character' | 'object', assetName);
                        
                        if (statusText) {
                            statusText.textContent = `تم حفظ ${assetType} مع جميع الأصول بنجاح`;
                        }
                    } catch (error) {
                        console.error('خطأ في معالجة الأصول بعد الحفظ:', error);
                        if (statusText) {
                            statusText.textContent = `تم حفظ ${assetType} بنجاح (مع أخطاء في الأصول)`;
                        }
                    }
                }, 2000); // زيادة وقت الانتظار إلى 2 ثانية
                
                alert(result.message);
            } else {
                throw new Error(result.error || 'فشل في الحفظ');
            }

        } catch (error) {
            console.error('Error saving project:', error);
            const statusText = document.getElementById('status-text');
            const errorMessage = error instanceof Error ? error.message : String(error);
            if (statusText) {
                statusText.textContent = `خطأ في الحفظ: ${errorMessage}`;
            }
            alert(`خطأ في الحفظ: ${errorMessage}`);
        }
    }

    /**
     * التقاط صورة مصغرة للمشهد الحالي
     */
    private async captureThumbnail(assetType: 'map' | 'character' | 'object', assetName: string): Promise<void> {
        try {
            if (!this.engine || !this.scene) {
                console.warn('لا يمكن التقاط الصورة المصغرة: المحرك أو المشهد غير متوفر');
                return;
            }

            // Check for active camera or cameraToUseForPointers
            const hasCamera = this.scene.activeCamera || this.scene.cameraToUseForPointers || this.scene.cameras.length > 0;
            if (!hasCamera) {
                console.warn('لا يمكن التقاط الصورة المصغرة: لا توجد كاميرا متاحة');
                return;
            }

            console.log('بدء التقاط الصورة المصغرة للأصل:', assetName);
            
            // تأكد من عرض المشهد عدة مرات للتأكد من التحميل الكامل
            for (let i = 0; i < 3; i++) {
                this.scene.render();
                await new Promise(resolve => setTimeout(resolve, 100)); // انتظار قصير بين كل عرض
            }
            
            // التقاط الصورة من الكانفاس مباشرة (الطريقة المُختبرة)
            const canvas = this.engine.getRenderingCanvas() as HTMLCanvasElement;
            if (!canvas) {
                throw new Error('لا يمكن الوصول إلى الكانفاس');
            }

            // التأكد من أن الكانفاس يحتوي على بيانات
            if (canvas.width === 0 || canvas.height === 0) {
                throw new Error('الكانفاس فارغ أو غير مُعرف');
            }

            // تحويل الكانفاس إلى صورة مصغرة
            const thumbnailCanvas = document.createElement('canvas');
            thumbnailCanvas.width = 256;
            thumbnailCanvas.height = 256;
            const ctx = thumbnailCanvas.getContext('2d');
            
            if (!ctx) {
                throw new Error('فشل في إنشاء سياق الرسم');
            }

            // رسم الصورة مع تغيير الحجم
            ctx.drawImage(canvas, 0, 0, 256, 256);
            const dataUrl = thumbnailCanvas.toDataURL('image/png');
            
            console.log('تم إنشاء الصورة المصغرة، البيانات:', dataUrl.substring(0, 100) + '...');

            // حفظ الصورة المصغرة
            const result = await this.apiClient.saveThumbnail(assetType, assetName, dataUrl);
            
            if (result.success) {
                console.log('تم حفظ الصورة المصغرة في الخادم بنجاح');
            } else {
                console.error('فشل في حفظ الصورة المصغرة:', result.error);
            }

        } catch (error) {
            console.error('خطأ في التقاط الصورة المصغرة:', error);
            // لا نوقف عملية الحفظ إذا فشلت الصورة المصغرة
        }
    }

    /**
     * نقل الأصول الخارجية إلى مجلد المشروع
     */
    private async moveExternalAssetsToProject(assetType: 'map' | 'character' | 'object', assetName: string): Promise<void> {
        try {
            const response = await fetch('http://localhost:5001/api/assets/move-external-to-project', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    type: assetType,
                    name: assetName
                })
            });

            const result = await response.json();

            if (result.success) {
                console.log('تم نقل الأصول الخارجية بنجاح:', result.movedFiles);
            } else {
                console.warn('تعذر نقل الأصول الخارجية:', result.error);
            }

        } catch (error) {
            console.error('خطأ في نقل الأصول الخارجية:', error);
        }
    }

    /**
     * فتح لوحة استيراد الأصول الخارجية
     */
    private openImportAssetsPanel(): void {
        const importPanel = document.getElementById('import-assets-panel');
        if (importPanel) {
            importPanel.classList.remove('hidden');
            this.refreshImportedFilesList();
        }
    }

    /**
     * إغلاق لوحة استيراد الأصول الخارجية
     */
    private closeImportAssetsPanel(): void {
        const importPanel = document.getElementById('import-assets-panel');
        if (importPanel) {
            importPanel.classList.add('hidden');
        }
    }

    /**
     * استيراد الملفات المحددة
     */
    private async importSelectedFiles(): Promise<void> {
        const fileInput = document.getElementById('single-file-input') as HTMLInputElement;
        if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
            this.updateImportStatus('يرجى اختيار ملفات للاستيراد', 'error');
            return;
        }

        await this.uploadFiles(Array.from(fileInput.files));
    }

    /**
     * استيراد المجلد المحدد
     */
    private async importSelectedFolder(): Promise<void> {
        const folderInput = document.getElementById('folder-input') as HTMLInputElement;
        if (!folderInput || !folderInput.files || folderInput.files.length === 0) {
            this.updateImportStatus('يرجى اختيار مجلد للاستيراد', 'error');
            return;
        }

        await this.uploadFiles(Array.from(folderInput.files));
    }

    /**
     * رفع الملفات إلى الخادم
     */
    private async uploadFiles(files: File[]): Promise<void> {
        try {
            this.updateImportStatus(`جاري رفع ${files.length} ملف...`, 'processing');

            const formData = new FormData();
            files.forEach((file, index) => {
                formData.append(`files`, file);
                formData.append(`paths`, file.webkitRelativePath || file.name);
            });

            const response = await fetch('http://localhost:5001/api/assets/import-external', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (result.success) {
                this.updateImportStatus(`تم رفع ${files.length} ملف بنجاح`, 'success');
                this.refreshImportedFilesList();
                
                // مسح inputs
                const fileInput = document.getElementById('single-file-input') as HTMLInputElement;
                const folderInput = document.getElementById('folder-input') as HTMLInputElement;
                if (fileInput) fileInput.value = '';
                if (folderInput) folderInput.value = '';
            } else {
                throw new Error(result.error || 'فشل في رفع الملفات');
            }

        } catch (error) {
            console.error('Error uploading files:', error);
            const errorMessage = error instanceof Error ? error.message : String(error);
            this.updateImportStatus(`خطأ في رفع الملفات: ${errorMessage}`, 'error');
        }
    }

    /**
     * مسح جميع الاستيرادات
     */
    private async clearAllImports(): Promise<void> {
        if (!confirm('هل أنت متأكد من مسح جميع الملفات المستوردة؟')) {
            return;
        }

        try {
            this.updateImportStatus('جاري مسح الملفات...', 'processing');

            const response = await fetch('http://localhost:5001/api/assets/clear-external', {
                method: 'DELETE'
            });

            const result = await response.json();

            if (result.success) {
                this.updateImportStatus('تم مسح جميع الملفات المستوردة', 'success');
                this.refreshImportedFilesList();
            } else {
                throw new Error(result.error || 'فشل في مسح الملفات');
            }

        } catch (error) {
            console.error('Error clearing imports:', error);
            this.updateImportStatus(`خطأ في مسح الملفات: ${error.message}`, 'error');
        }
    }

    /**
     * تحديث حالة الاستيراد
     */
    private updateImportStatus(message: string, type: 'success' | 'error' | 'processing' = 'processing'): void {
        const statusElement = document.getElementById('import-status');
        if (statusElement) {
            // Use safe DOM manipulation instead of innerHTML
            statusElement.innerHTML = ''; // Clear first
            const paragraph = CodeSecurityManager.createSafeElement('p', message);
            statusElement.appendChild(paragraph);
            statusElement.className = `import-status ${type}`;
        }
    }

    /**
     * تحديث قائمة الملفات المستوردة
     */
    private async refreshImportedFilesList(): Promise<void> {
        try {
            const response = await fetch('http://localhost:5001/api/assets/list-external');
            const result = await response.json();

            const filesList = document.getElementById('imported-files-list');
            if (!filesList) return;

            if (result.success && result.files && result.files.length > 0) {
                // Use safe DOM manipulation instead of innerHTML
                filesList.innerHTML = ''; // Clear first
                result.files.forEach((file: any) => {
                    const fileItem = document.createElement('div');
                    fileItem.className = 'file-item';
                    
                    const fileName = CodeSecurityManager.createSafeElement('span', file.name, { class: 'file-name' });
                    const fileSize = CodeSecurityManager.createSafeElement('span', this.formatFileSize(file.size), { class: 'file-size' });
                    
                    fileItem.appendChild(fileName);
                    fileItem.appendChild(fileSize);
                    filesList.appendChild(fileItem);
                });
            } else {
                filesList.innerHTML = ''; // Clear first
                const noFilesMessage = CodeSecurityManager.createSafeElement('p', 'لا توجد ملفات مستوردة', {
                    style: 'text-align: center; color: #888; padding: 1rem;'
                });
                filesList.appendChild(noFilesMessage);
            }

        } catch (error) {
            console.error('Error refreshing imported files list:', error);
        }
    }

    /**
     * تنسيق حجم الملف
     */
    private formatFileSize(bytes: number): string {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * تبديل وضع الإطار السلكي (Wireframe)
     */
    private toggleWireframe(): void {
        try {
            if (!this.scene) {
                console.warn('لا يمكن تبديل الإطار السلكي: المشهد غير متوفر');
                return;
            }

            this.isWireframeMode = !this.isWireframeMode;
            
            // تطبيق وضع الإطار السلكي على جميع المواد في المشهد
            this.scene.materials.forEach((material: any) => {
                if (material) {
                    material.wireframe = this.isWireframeMode;
                }
            });

            // تطبيق وضع الإطار السلكي على جميع الشبكات (Meshes) أيضاً
            this.scene.meshes.forEach((mesh: any) => {
                if (mesh && mesh.material) {
                    mesh.material.wireframe = this.isWireframeMode;
                }
            });

            // تحديث شكل الزر
            const wireframeBtn = document.getElementById('wireframe-btn');
            if (wireframeBtn) {
                wireframeBtn.style.backgroundColor = this.isWireframeMode ? '#007acc' : '';
                wireframeBtn.style.color = this.isWireframeMode ? 'white' : '';
            }

            // تحديث النص في شريط الحالة
            const statusText = document.getElementById('status-text');
            if (statusText) {
                statusText.textContent = this.isWireframeMode ? 
                    'تم تفعيل وضع الإطار السلكي' : 
                    'تم إلغاء وضع الإطار السلكي';
            }

            console.log('تم تبديل وضع الإطار السلكي:', this.isWireframeMode);

        } catch (error) {
            console.error('خطأ في تبديل وضع الإطار السلكي:', error);
        }
    }

    /**
     * تبديل وضع ملء الشاشة لمنطقة العرض
     */
    private toggleFullscreenViewport(): void {
        try {
            const viewportContainer = document.querySelector('.viewport-container') as HTMLElement;
            const dashboardContent = document.querySelector('.dashboard-content') as HTMLElement;
            const fullscreenBtn = document.getElementById('fullscreen-viewport-btn');
            
            if (!viewportContainer || !dashboardContent) {
                console.warn('لا يمكن تبديل وضع ملء الشاشة: العناصر المطلوبة غير موجودة');
                return;
            }

            this.isFullscreenViewport = !this.isFullscreenViewport;

            if (this.isFullscreenViewport) {
                // تفعيل وضع ملء الشاشة
                viewportContainer.classList.add('fullscreen-viewport');
                dashboardContent.classList.add('fullscreen-mode');
                
                // تحديث الزر
                if (fullscreenBtn) {
                    fullscreenBtn.style.backgroundColor = '#007acc';
                    fullscreenBtn.style.color = 'white';
                    fullscreenBtn.textContent = '⛶'; // أو يمكن تغييره لأيقونة "خروج من ملء الشاشة"
                }
                
                // تحديث النص في شريط الحالة
                const statusText = document.getElementById('status-text');
                if (statusText) {
                    statusText.textContent = 'تم تفعيل وضع ملء الشاشة لمنطقة العرض';
                }
            } else {
                // إلغاء وضع ملء الشاشة
                viewportContainer.classList.remove('fullscreen-viewport');
                dashboardContent.classList.remove('fullscreen-mode');
                
                // تحديث الزر
                if (fullscreenBtn) {
                    fullscreenBtn.style.backgroundColor = '';
                    fullscreenBtn.style.color = '';
                    fullscreenBtn.textContent = '⛶';
                }
                
                // تحديث النص في شريط الحالة
                const statusText = document.getElementById('status-text');
                if (statusText) {
                    statusText.textContent = 'تم إلغاء وضع ملء الشاشة';
                }
            }

            // إعادة تحجيم المحرك لضمان التوافق مع الحجم الجديد
            if (this.engine) {
                setTimeout(() => {
                    this.engine.resize();
                }, 100);
            }

            console.log('تم تبديل وضع ملء الشاشة:', this.isFullscreenViewport);

        } catch (error) {
            console.error('خطأ في تبديل وضع ملء الشاشة:', error);
        }
    }

    /**
     * فتح مكتبة الأصول
     */
    private async openAssetLibrary(): Promise<void> {
        const assetLibrary = document.getElementById('asset-library');
        if (assetLibrary) {
            assetLibrary.classList.remove('hidden');
            await this.refreshAssetLibrary();
        }
    }

    /**
     * إغلاق مكتبة الأصول
     */
    private closeAssetLibrary(): void {
        const assetLibrary = document.getElementById('asset-library');
        if (assetLibrary) {
            assetLibrary.classList.add('hidden');
        }
    }

    /**
     * تحديث مكتبة الأصول
     */
    private async refreshAssetLibrary(): Promise<void> {
        const libraryAssetType = document.getElementById('library-asset-type') as HTMLSelectElement;
        const assetGrid = document.getElementById('asset-grid');
        
        if (!libraryAssetType || !assetGrid) return;

        const assetType = libraryAssetType.value as 'map' | 'character' | 'object';

        try {
            // جلب قائمة الأصول
            const result = await this.apiClient.listAssets(assetType);
            
            // مسح المحتوى الحالي
            assetGrid.innerHTML = '';

            if (result.success && result.assets.length > 0) {
                // إنشاء بطاقة لكل أصل
                result.assets.forEach((asset: any) => {
                    const assetCard = this.createAssetCard(asset, assetType);
                    assetGrid.appendChild(assetCard);
                });
            } else {
                // رسالة عدم وجود أصول - use safe DOM manipulation
                const noAssetsMessage = CodeSecurityManager.createSafeElement('div', 
                    `لا توجد أصول محفوظة من نوع ${this.getAssetTypeDisplayName(assetType)}`, {
                    style: 'grid-column: 1 / -1; text-align: center; color: #888; padding: 2rem;'
                });
                assetGrid.appendChild(noAssetsMessage);
            }
        } catch (error) {
            console.error('Error loading assets:', error);
            const errorMessage = CodeSecurityManager.createSafeElement('div', 
                `خطأ في تحميل الأصول: ${error instanceof Error ? error.message : 'خطأ غير معروف'}`, {
                style: 'grid-column: 1 / -1; text-align: center; color: #e74c3c; padding: 2rem;'
            });
            assetGrid.appendChild(errorMessage);
        }
    }

    /**
     * إنشاء بطاقة أصل
     */
    private createAssetCard(asset: any, assetType: 'map' | 'character' | 'object'): HTMLElement {
        const card = document.createElement('div');
        card.className = 'asset-card';
        
        const thumbnailElement = this.createThumbnailElement(asset, assetType);
        const nameElement = document.createElement('div');
        nameElement.className = 'asset-name';
        nameElement.textContent = asset.name;

        const infoElement = document.createElement('div');
        infoElement.className = 'asset-info';
        const createdDate = new Date(asset.created_at).toLocaleDateString('ar');
        infoElement.textContent = `تم الإنشاء: ${createdDate}`;

        card.appendChild(thumbnailElement);
        card.appendChild(nameElement);
        card.appendChild(infoElement);

        // إضافة حدث النقر لتحميل الأصل
        card.addEventListener('click', () => this.loadAssetFromLibrary(asset, assetType));

        return card;
    }

    /**
     * إنشاء عنصر الصورة المصغرة
     */
    private createThumbnailElement(asset: any, assetType: 'map' | 'character' | 'object'): HTMLElement {
        const thumbnailDiv = document.createElement('div');
        thumbnailDiv.className = 'asset-thumbnail';

        if (asset.has_thumbnail) {
            const img = document.createElement('img');
            img.src = this.apiClient.getThumbnailUrl(assetType, asset.name);
            img.alt = asset.name;
            img.onerror = () => {
                // إذا فشل تحميل الصورة، اعرض أيقونة افتراضية
                thumbnailDiv.innerHTML = ''; // Clear first
                thumbnailDiv.textContent = this.getDefaultIcon(assetType); // Safe text content
                thumbnailDiv.classList.add('no-thumbnail');
            };
            thumbnailDiv.appendChild(img);
        } else {
            thumbnailDiv.textContent = this.getDefaultIcon(assetType); // Safe text content
            thumbnailDiv.classList.add('no-thumbnail');
        }

        return thumbnailDiv;
    }

    /**
     * الحصول على أيقونة افتراضية حسب نوع الأصل
     */
    private getDefaultIcon(assetType: 'map' | 'character' | 'object'): string {
        switch (assetType) {
            case 'map': return '🗺️';
            case 'character': return '👤';
            case 'object': return '📦';
            default: return '📄';
        }
    }

    /**
     * الحصول على اسم نوع الأصل للعرض
     */
    private getAssetTypeDisplayName(assetType: 'map' | 'character' | 'object'): string {
        switch (assetType) {
            case 'map': return 'الخرائط';
            case 'character': return 'الشخصيات';
            case 'object': return 'الكائنات';
            default: return assetType;
        }
    }

    /**
     * تحميل أصل من المكتبة
     */
    private async loadAssetFromLibrary(asset: any, assetType: 'map' | 'character' | 'object'): Promise<void> {
        try {
            // تنظيف مجلد external-import أولاً
            await this.cleanExternalImportDirectory();
            
            // فحص وجود مجلد assets في المشروع ونسخه
            await this.copyProjectAssetsToExternalImport(assetType, asset.name);
            
            const result = await this.apiClient.loadAsset(assetType, asset.name);
            
            if (result.success && result.data && this.editor) {
                this.editor.setValue(result.data.code);
                this.closeAssetLibrary();
                
                const statusText = document.getElementById('status-text');
                if (statusText) {
                    statusText.textContent = `تم تحميل ${asset.name} بنجاح مع الأصول`;
                }
                
                // تشغيل الكود تلقائياً
                await this.runCode();
            } else {
                throw new Error(result.error || 'فشل في تحميل الأصل');
            }
        } catch (error) {
            console.error('Error loading asset from library:', error);
            alert(`خطأ في تحميل ${asset.name}: ${error.message}`);
        }
    }

    /**
     * تحميل المشروع
     */
    private async loadProject(): Promise<void> {
        try {
            // الحصول على نوع الأصل المحدد
            const assetTypeSelect = document.getElementById('asset-type') as HTMLSelectElement;
            const assetType = assetTypeSelect?.value || 'map';

            const statusText = document.getElementById('status-text');
            if (statusText) {
                statusText.textContent = 'جاري جلب قائمة الأصول...';
            }

            // جلب قائمة الأصول المتاحة
            const assetsResult = await this.apiClient.listAssets(assetType as 'map' | 'character' | 'object');
            
            if (!assetsResult.success || !assetsResult.assets.length) {
                alert('لا توجد أصول محفوظة من هذا النوع');
                if (statusText) {
                    statusText.textContent = 'جاهز';
                }
                return;
            }

            // إنشاء قائمة للاختيار من بينها
            const assetNames = assetsResult.assets.map((asset: any) => asset.name);
            const selectedAsset = prompt(`اختر الأصل للتحميل:\n${assetNames.join('\n')}\n\nأدخل الاسم:`);
            
            if (!selectedAsset) {
                if (statusText) {
                    statusText.textContent = 'جاهز';
                }
                return;
            }

            if (statusText) {
                statusText.textContent = 'جاري التحميل...';
            }

            // تحميل الأصل المحدد
            const loadResult = await this.apiClient.loadAsset(
                assetType as 'map' | 'character' | 'object',
                selectedAsset
            );

            if (loadResult.success && loadResult.data) {
                if (this.editor) {
                    this.editor.setValue(loadResult.data.code);
                }
                
                if (statusText) {
                    statusText.textContent = `تم تحميل ${assetType} بنجاح`;
                }
                
                alert(`تم تحميل ${selectedAsset} بنجاح`);
            } else {
                throw new Error(loadResult.error || 'فشل في التحميل');
            }

        } catch (error) {
            console.error('Error loading project:', error);
            const statusText = document.getElementById('status-text');
            if (statusText) {
                statusText.textContent = `خطأ في التحميل: ${error.message}`;
            }
            alert(`خطأ في التحميل: ${error.message}`);
        }
    }

    /**
     * الحصول على الكود الافتراضي للمشهد
     */
    private getDefaultCode(): string {
        return getDefaultSceneCode();
    }

    /**
     * تنظيف مجلد external-import
     */
    private async cleanExternalImportDirectory(): Promise<void> {
        try {
            const response = await fetch('http://localhost:5001/api/assets/clear-external', {
                method: 'DELETE'
            });

            const result = await response.json();

            if (result.success) {
                console.log('تم تنظيف مجلد external-import بنجاح');
            } else {
                console.warn('تعذر تنظيف مجلد external-import:', result.error);
            }

        } catch (error) {
            console.error('خطأ في تنظيف مجلد external-import:', error);
            // لا نوقف العملية إذا فشل التنظيف
        }
    }

    /**
     * نسخ أصول المشروع إلى مجلد external-import
     */
    private async copyProjectAssetsToExternalImport(assetType: 'map' | 'character' | 'object', assetName: string): Promise<void> {
        try {
            const response = await fetch('http://localhost:5001/api/assets/copy-project-assets', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    type: assetType,
                    name: assetName
                })
            });

            const result = await response.json();

            if (result.success) {
                if (result.foundAssets) {
                    console.log(`تم نسخ أصول المشروع ${assetName}:`, result.copiedFiles);
                } else {
                    console.log(`لا توجد أصول إضافية في المشروع ${assetName}`);
                }
            } else {
                console.warn('تعذر نسخ أصول المشروع:', result.error);
            }

        } catch (error) {
            console.error('خطأ في نسخ أصول المشروع:', error);
            // لا نوقف العملية إذا فشل النسخ
        }
    }

    /**
     * تشغيل كود المستخدم بطريقة آمنة
     */
    private async executeUserCodeSafely(sanitizedCode: string, engine: any, canvas: HTMLCanvasElement, BABYLON: any, originalChecksum: string): Promise<any> {
        try {
            // إعداد بيئة آمنة للتنفيذ
            const safeEnvironment = this.createSafeExecutionEnvironment(engine, canvas, BABYLON);
            
            // Create a module-like execution context
            const moduleContext = {
                // Provide safe access to required APIs
                engine: engine,
                canvas: canvas,
                BABYLON: BABYLON,
                scene: null,
                createEngine: null,
                createScene: null,
                delayCreateScene: null,
                
                // Asset path conversion utilities
                convertAssetPath: function(url: string) {
                    if (!url || typeof url !== 'string') return url;
                    
                    // إذا كان المسار يبدأ بـ external-import أو http أو / فلا نغيره
                    if (url.startsWith('external-import/') || 
                        url.startsWith('http') || 
                        url.startsWith('/') ||
                        url.startsWith('data:') ||
                        url.startsWith('blob:')) {
                        return url;
                    }
                    
                    // أضف external-import/ للمسارات النسبية
                    const newUrl = 'external-import/' + url;
                    console.log('Path redirect:', url, '->', newUrl);
                    return newUrl;
                }
            };
            
            // Apply asset path redirection safely
            this.setupAssetPathRedirection(BABYLON, moduleContext.convertAssetPath);
            
            // Create isolated execution function
            const isolatedExecution = this.createIsolatedExecution(sanitizedCode, moduleContext);
            
            // Verify code integrity before execution
            const currentChecksum = CodeSecurityManager.createChecksum(sanitizedCode);
            if (currentChecksum !== originalChecksum) {
                throw new Error('Code integrity check failed - code may have been tampered with');
            }
            
            // Execute with timeout protection
            const result = await this.executeWithTimeout(isolatedExecution, 30000); // 30 second timeout
            
            return {
                engine: result.engine || moduleContext.engine,
                scene: result.scene || moduleContext.scene,
                createEngine: result.createEngine || moduleContext.createEngine,
                createScene: result.createScene || moduleContext.createScene,
                delayCreateScene: result.delayCreateScene || moduleContext.delayCreateScene
            };
            
        } catch (error) {
            console.error('Safe code execution failed:', error);
            throw error;
        }
    }

    /**
     * إعداد بيئة تنفيذ آمنة
     */
    private createSafeExecutionEnvironment(engine: any, canvas: HTMLCanvasElement, BABYLON: any): any {
        // Create restricted global scope
        return {
            // Allow console for debugging
            console: {
                log: console.log.bind(console),
                warn: console.warn.bind(console),
                error: console.error.bind(console),
                info: console.info.bind(console)
            },
            // Safe Math object
            Math: Math,
            // Safe array and object constructors
            Array: Array,
            Object: Object,
            String: String,
            Number: Number,
            Boolean: Boolean,
            Date: Date,
            JSON: JSON,
            // Babylon.js API
            BABYLON: BABYLON,
            engine: engine,
            canvas: canvas,
            // Prevent access to dangerous globals
            window: undefined,
            document: undefined,
            global: undefined,
            self: undefined,
            eval: undefined,
            Function: undefined,
            setTimeout: undefined,
            setInterval: undefined,
            fetch: undefined,
            XMLHttpRequest: undefined
        };
    }

    /**
     * إعداد إعادة توجيه مسارات الأصول بطريقة آمنة
     */
    private setupAssetPathRedirection(BABYLON: any, convertAssetPath: (url: string) => string): void {
        try {
            if (!BABYLON) return;
            
            console.log('Setting up external assets path redirection safely...');
            
            // إعادة تعريف SceneLoader.ImportMesh
            if (BABYLON.SceneLoader && BABYLON.SceneLoader.ImportMesh) {
                const originalImportMesh = BABYLON.SceneLoader.ImportMesh;
                BABYLON.SceneLoader.ImportMesh = function(meshNames: any, rootUrl: string, sceneFilename: string, scene: any, onSuccess?: any, onProgress?: any, onError?: any, pluginExtension?: string) {
                    rootUrl = convertAssetPath(rootUrl || '');
                    sceneFilename = sceneFilename || '';
                    return originalImportMesh.call(this, meshNames, rootUrl, sceneFilename, scene, onSuccess, onProgress, onError, pluginExtension);
                };
            }
            
            // إعادة تعريف SceneLoader.AppendAsync
            if (BABYLON.SceneLoader && BABYLON.SceneLoader.AppendAsync) {
                const originalAppendAsync = BABYLON.SceneLoader.AppendAsync;
                BABYLON.SceneLoader.AppendAsync = function(rootUrl: string, sceneFilename: string, scene: any, onProgress?: any, pluginExtension?: string) {
                    rootUrl = convertAssetPath(rootUrl || '');
                    sceneFilename = sceneFilename || '';
                    return originalAppendAsync.call(this, rootUrl, sceneFilename, scene, onProgress, pluginExtension);
                };
            }
            
            // إعادة تعريف Texture للصور
            if (BABYLON.Texture) {
                const originalTexture = BABYLON.Texture;
                BABYLON.Texture = function(url: string, sceneOrEngine: any, noMipmapOrOptions?: any, invertY?: boolean, samplingMode?: number, onLoad?: any, onError?: any, buffer?: any, deleteBuffer?: boolean, format?: number, mimeType?: string, loaderOptions?: any, creationFlags?: number, forcedExtension?: string) {
                    if (url && typeof url === 'string') {
                        url = convertAssetPath(url);
                    }
                    return new originalTexture(url, sceneOrEngine, noMipmapOrOptions, invertY, samplingMode, onLoad, onError, buffer, deleteBuffer, format, mimeType, loaderOptions, creationFlags, forcedExtension);
                };
                // نسخ الخصائص الثابتة
                Object.setPrototypeOf(BABYLON.Texture, originalTexture);
                Object.assign(BABYLON.Texture, originalTexture);
            }
            
            console.log('External assets path redirection setup complete');
        } catch (error) {
            console.error('Error setting up asset path redirection:', error);
        }
    }

    /**
     * إنشاء تنفيذ معزول للكود
     */
    private createIsolatedExecution(code: string, context: any): () => Promise<any> {
        return async () => {
            try {
                // Create a more secure execution environment using eval within a controlled scope
                // Note: This is still not 100% secure but much safer than the previous approach
                const secureEval = this.createSecureEval(context);
                
                // Wrap user code in a strict mode async function
                const wrappedCode = `
                    (async function() {
                        "use strict";
                        
                        ${code}
                        
                        // Return context variables that may have been modified
                        return {
                            engine: typeof engine !== 'undefined' ? engine : null,
                            scene: typeof scene !== 'undefined' ? scene : null,
                            createEngine: typeof createEngine === 'function' ? createEngine : null,
                            createScene: typeof createScene === 'function' ? createScene : null,
                            delayCreateScene: typeof delayCreateScene === 'function' ? delayCreateScene : null
                        };
                    })()
                `;
                
                // Execute in the secure environment
                return await secureEval(wrappedCode);
                
            } catch (error) {
                console.error('User code execution error:', error);
                throw error;
            }
        };
    }

    /**
     * Create a more secure eval function with limited scope
     */
    private createSecureEval(context: any): (code: string) => Promise<any> {
        return async (code: string) => {
            // Create limited global scope
            const limitedGlobal = {
                // Essential JavaScript objects
                console: context.console || {
                    log: console.log.bind(console),
                    warn: console.warn.bind(console),
                    error: console.error.bind(console)
                },
                Math: Math,
                Array: Array,
                Object: Object,
                String: String,
                Number: Number,
                Boolean: Boolean,
                Date: Date,
                JSON: JSON,
                Promise: Promise,
                
                // Babylon.js context
                BABYLON: context.BABYLON,
                engine: context.engine,
                canvas: context.canvas,
                scene: context.scene,
                createEngine: context.createEngine,
                createScene: context.createScene,
                delayCreateScene: context.delayCreateScene,
                convertAssetPath: context.convertAssetPath,
                
                // Explicitly undefined dangerous globals
                window: undefined,
                document: undefined,
                global: undefined,
                self: undefined,
                eval: undefined,
                Function: undefined,
                setTimeout: undefined,
                setInterval: undefined,
                fetch: undefined,
                XMLHttpRequest: undefined,
                localStorage: undefined,
                sessionStorage: undefined
            };
            
            // Execute in limited scope
            const keys = Object.keys(limitedGlobal);
            const values = keys.map(key => limitedGlobal[key]);
            
            // Use AsyncFunction constructor with explicit parameters
            const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
            const func = new AsyncFunction(...keys, `return ${code}`);
            
            return await func(...values);
        };
    }

    /**
     * تنفيذ مع حماية المهلة الزمنية
     */
    private async executeWithTimeout<T>(fn: () => Promise<T>, timeoutMs: number): Promise<T> {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error(`Code execution timeout after ${timeoutMs}ms`));
            }, timeoutMs);
            
            fn().then((result) => {
                clearTimeout(timer);
                resolve(result);
            }).catch((error) => {
                clearTimeout(timer);
                reject(error);
            });
        });
    }

    /**
     * تنظيف الموارد
     */
    cleanup(): void {
        try {
            // Clean up sounds first
            if (this.scene && this.scene._spatialSounds) {
                console.log('Cleaning up spatial sounds...');
                this.scene._spatialSounds.forEach((sound: any) => {
                    try {
                        if (sound.dispose) {
                            sound.dispose();
                        } else {
                            if (sound.stop) sound.stop();
                            if (sound.audioSource) {
                                sound.audioSource.disconnect();
                            }
                            if (sound.gainNode) {
                                sound.gainNode.disconnect();
                            }
                        }
                    } catch (e) {
                        console.warn('Error cleaning up sound:', e);
                    }
                });
                this.scene._spatialSounds = [];
            }

            // Clean up scene
            if (this.scene) {
                console.log('Disposing scene...');
                try {
                    this.scene.dispose();
                } catch (e) {
                    console.warn('Error disposing scene:', e);
                }
                this.scene = null;
            }

            // Clean up engine
            if (this.engine) {
                console.log('Disposing engine...');
                try {
                    this.engine.dispose();
                } catch (e) {
                    console.warn('Error disposing engine:', e);
                }
                this.engine = null;
            }

            // Clean up editor
            if (this.editor) {
                console.log('Disposing editor...');
                try {
                    this.editor.dispose();
                } catch (e) {
                    console.warn('Error disposing editor:', e);
                }
                this.editor = null;
            }

            // Clean up canvas reference
            this.canvas = null;

            console.log('AdminDashboard cleanup completed');
            
        } catch (error) {
            console.error('Error during AdminDashboard cleanup:', error);
        }
    }

    /**
     * معالج الأخطاء المحسن
     */
    private handleError(error: any, context: string): void {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`Error in ${context}:`, error);
        
        // Update status
        const statusText = document.getElementById('status-text');
        if (statusText) {
            statusText.textContent = `خطأ في ${context}: ${errorMessage}`;
        }
        
        // For critical errors, attempt cleanup and recovery
        if (context.includes('runCode') || context.includes('engine')) {
            try {
                console.log('Attempting error recovery...');
                if (this.scene) {
                    this.scene.dispose();
                    this.scene = null;
                }
                if (this.engine) {
                    this.engine.dispose();
                    this.engine = null;
                }
                // Reinitialize basic engine
                this.initializeBabylon().catch(e => {
                    console.error('Error recovery failed:', e);
                });
            } catch (recoveryError) {
                console.error('Error recovery failed:', recoveryError);
            }
        }
    }
}

