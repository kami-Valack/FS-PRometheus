import os
import stat
import time
import hashlib
import threading
import queue
from tkinter import *
from tkinter import ttk, filedialog, messagebox, simpledialog
from collections import defaultdict
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class AdvancedFileMonitor(FileSystemEventHandler):
    def __init__(self, log_callback, alert_callback):
        super().__init__()
        self.log_callback = log_callback
        self.alert_callback = alert_callback
        self.checksums = {}
        self.suspicious_patterns = [
            b'MZ',  # Executáveis Windows
            b'\x7fELF',  # Executáveis Linux
            b'<?php',  # Código PHP
            b'<script',  # JavaScript
            b'powershell',  # Comandos PowerShell
            b'cmd.exe'  # Comandos CMD
        ]
    
    def on_modified(self, event):
        if not event.is_directory:
            self.log_callback(f"Arquivo modificado: {event.src_path}")
            self.analyze_file(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self.log_callback(f"Arquivo criado: {event.src_path}")
            self.analyze_file(event.src_path)
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.log_callback(f"Arquivo removido: {event.src_path}")
    
    def on_moved(self, event):
        if not event.is_directory:
            self.log_callback(f"Arquivo movido: {event.src_path} -> {event.dest_path}")
            self.analyze_file(event.dest_path)
    
    def analyze_file(self, filepath):
        try:
            # Verificação de hash
            current_hash = self.calculate_hash(filepath)
            if filepath in self.checksums:
                if current_hash != self.checksums[filepath]:
                    self.alert_callback(f"Alerta: Conteúdo do arquivo alterado: {filepath}")
            self.checksums[filepath] = current_hash
            
            # Detecção de padrões suspeitos
            with open(filepath, 'rb') as f:
                content = f.read(1024)  # Ler apenas os primeiros bytes
                for pattern in self.suspicious_patterns:
                    if pattern in content:
                        self.alert_callback(f"ALERTA: Padrão suspeito detectado em {filepath}")
                        break
            
            # Verificação de permissões perigosas
            mode = os.stat(filepath).st_mode
            if mode & stat.S_IWOTH:  # Escrita por outros
                self.alert_callback(f"ALERTA: Permissões perigosas em {filepath} (escrita pública)")
            
        except Exception as e:
            self.log_callback(f"Erro ao analisar {filepath}: {str(e)}")
    
    def calculate_hash(self, filepath):
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

class PermissionManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gerenciador Avançado de Permissões e Monitoramento")
        self.root.geometry("1200x800")
        
        # Configuração do tema
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('Treeview', rowheight=25)
        
        # Variáveis de estado
        self.monitoring = False
        self.observer = None
        self.monitored_paths = {}
        self.file_queue = queue.Queue()
        self.setup_ui()
        
        # Iniciar thread para processar eventos
        self.process_events()
    
    def setup_ui(self):
        # Frame principal com notebook (abas)
        main_panel = ttk.PanedWindow(self.root, orient=HORIZONTAL)
        main_panel.pack(fill=BOTH, expand=True)
        
        # Painel esquerdo (controles)
        left_panel = ttk.Frame(main_panel, width=300, padding="10")
        main_panel.add(left_panel, weight=1)
        
        # Painel direito (visualização e logs)
        right_panel = ttk.Frame(main_panel, padding="10")
        main_panel.add(right_panel, weight=3)
        
        # Configuração do painel esquerdo
        self.setup_left_panel(left_panel)
        
        # Configuração do painel direito
        self.setup_right_panel(right_panel)
    
    def setup_left_panel(self, parent):
        # Controles de permissão
        perm_frame = ttk.LabelFrame(parent, text="Gerenciamento de Permissões", padding="10")
        perm_frame.pack(fill=X, pady=5)
        
        ttk.Label(perm_frame, text="Arquivo/Diretório:").grid(row=0, column=0, sticky=W)
        self.path_entry = ttk.Entry(perm_frame, width=30)
        self.path_entry.grid(row=1, column=0, columnspan=2, sticky=EW, padx=5)
        ttk.Button(perm_frame, text="Procurar", command=self.browse_path).grid(row=1, column=2)
        
        # Permissões do dono
        ttk.Label(perm_frame, text="Dono:").grid(row=2, column=0, sticky=W)
        self.owner_read = BooleanVar()
        self.owner_write = BooleanVar()
        self.owner_exec = BooleanVar()
        ttk.Checkbutton(perm_frame, text="Ler", variable=self.owner_read).grid(row=3, column=0, sticky=W)
        ttk.Checkbutton(perm_frame, text="Escrever", variable=self.owner_write).grid(row=3, column=1, sticky=W)
        ttk.Checkbutton(perm_frame, text="Executar", variable=self.owner_exec).grid(row=3, column=2, sticky=W)
        
        # Permissões do grupo
        ttk.Label(perm_frame, text="Grupo:").grid(row=4, column=0, sticky=W)
        self.group_read = BooleanVar()
        self.group_write = BooleanVar()
        self.group_exec = BooleanVar()
        ttk.Checkbutton(perm_frame, text="Ler", variable=self.group_read).grid(row=5, column=0, sticky=W)
        ttk.Checkbutton(perm_frame, text="Escrever", variable=self.group_write).grid(row=5, column=1, sticky=W)
        ttk.Checkbutton(perm_frame, text="Executar", variable=self.group_exec).grid(row=5, column=2, sticky=W)
        
        # Permissões públicos
        ttk.Label(perm_frame, text="Público:").grid(row=6, column=0, sticky=W)
        self.other_read = BooleanVar()
        self.other_write = BooleanVar()
        self.other_exec = BooleanVar()
        ttk.Checkbutton(perm_frame, text="Ler", variable=self.other_read).grid(row=7, column=0, sticky=W)
        ttk.Checkbutton(perm_frame, text="Escrever", variable=self.other_write).grid(row=7, column=1, sticky=W)
        ttk.Checkbutton(perm_frame, text="Executar", variable=self.other_exec).grid(row=7, column=2, sticky=W)
        
        ttk.Button(perm_frame, text="Aplicar Permissões", command=self.apply_permissions).grid(row=8, column=0, columnspan=3, pady=5)
        ttk.Button(perm_frame, text="Ler Permissões", command=self.read_permissions).grid(row=9, column=0, columnspan=3)
        
        # Monitoramento
        monitor_frame = ttk.LabelFrame(parent, text="Monitoramento de Arquivos", padding="10")
        monitor_frame.pack(fill=X, pady=5)
        
        self.recursive_var = BooleanVar(value=True)
        ttk.Checkbutton(monitor_frame, text="Monitorar recursivamente", variable=self.recursive_var).pack(anchor=W)
        
        ttk.Button(monitor_frame, text="Adicionar Diretório", command=self.add_directory).pack(fill=X, pady=2)
        ttk.Button(monitor_frame, text="Remover Diretório", command=self.remove_directory).pack(fill=X, pady=2)
        ttk.Button(monitor_frame, text="Iniciar Monitoramento", command=self.start_monitoring).pack(fill=X, pady=2)
        ttk.Button(monitor_frame, text="Parar Monitoramento", command=self.stop_monitoring).pack(fill=X, pady=2)
        
        # Análise de segurança
        security_frame = ttk.LabelFrame(parent, text="Análise de Segurança", padding="10")
        security_frame.pack(fill=X, pady=5)
        
        ttk.Button(security_frame, text="Verificar Vulnerabilidades", command=self.scan_vulnerabilities).pack(fill=X, pady=2)
        ttk.Button(security_frame, text="Auditar Permissões", command=self.audit_permissions).pack(fill=X, pady=2)
        ttk.Button(security_frame, text="Verificar Integridade", command=self.check_integrity).pack(fill=X, pady=2)
    
    def setup_right_panel(self, parent):
        # Notebook para múltiplas abas
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=BOTH, expand=True)
        
        # Aba de arquivos monitorados
        files_tab = ttk.Frame(self.notebook)
        self.notebook.add(files_tab, text="Arquivos Monitorados")
        
        self.tree = ttk.Treeview(files_tab, columns=("Permissões", "Tamanho", "Modificado", "Proprietário"), selectmode="extended")
        self.tree.heading("#0", text="Caminho")
        self.tree.heading("Permissões", text="Permissões")
        self.tree.heading("Tamanho", text="Tamanho")
        self.tree.heading("Modificado", text="Modificado")
        self.tree.heading("Proprietário", text="Proprietário")
        
        vsb = ttk.Scrollbar(files_tab, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(files_tab, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        files_tab.grid_rowconfigure(0, weight=1)
        files_tab.grid_columnconfigure(0, weight=1)
        
        # Aba de logs
        log_tab = ttk.Frame(self.notebook)
        self.notebook.add(log_tab, text="Logs de Atividade")
        
        self.log_text = Text(log_tab, wrap=WORD)
        self.log_text.tag_config("ALERT", foreground="red")
        self.log_text.tag_config("WARNING", foreground="orange")
        self.log_text.tag_config("INFO", foreground="blue")
        
        log_scroll = ttk.Scrollbar(log_tab, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll.grid(row=0, column=1, sticky="ns")
        
        log_tab.grid_rowconfigure(0, weight=1)
        log_tab.grid_columnconfigure(0, weight=1)
        
        # Aba de estatísticas
        stats_tab = ttk.Frame(self.notebook)
        self.notebook.add(stats_tab, text="Estatísticas")
        
        self.stats_text = Text(stats_tab, wrap=WORD)
        stats_scroll = ttk.Scrollbar(stats_tab, command=self.stats_text.yview)
        self.stats_text.configure(yscrollcommand=stats_scroll.set)
        
        self.stats_text.grid(row=0, column=0, sticky="nsew")
        stats_scroll.grid(row=0, column=1, sticky="ns")
        
        stats_tab.grid_rowconfigure(0, weight=1)
        stats_tab.grid_columnconfigure(0, weight=1)
    
    def browse_path(self):
        path = filedialog.askopenfilename()
        if not path:
            path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, END)
            self.path_entry.insert(0, path)
            self.read_permissions()
    
    def read_permissions(self):
        path = self.path_entry.get()
        if not path:
            return
        
        try:
            st = os.stat(path)
            mode = st.st_mode
            
            # Limpar seleções anteriores
            self.owner_read.set(False)
            self.owner_write.set(False)
            self.owner_exec.set(False)
            self.group_read.set(False)
            self.group_write.set(False)
            self.group_exec.set(False)
            self.other_read.set(False)
            self.other_write.set(False)
            self.other_exec.set(False)
            
            # Definir permissões do dono
            if mode & stat.S_IRUSR:
                self.owner_read.set(True)
            if mode & stat.S_IWUSR:
                self.owner_write.set(True)
            if mode & stat.S_IXUSR:
                self.owner_exec.set(True)
            
            # Definir permissões do grupo
            if mode & stat.S_IRGRP:
                self.group_read.set(True)
            if mode & stat.S_IWGRP:
                self.group_write.set(True)
            if mode & stat.S_IXGRP:
                self.group_exec.set(True)
            
            # Definir permissões públicas
            if mode & stat.S_IROTH:
                self.other_read.set(True)
            if mode & stat.S_IWOTH:
                self.other_write.set(True)
            if mode & stat.S_IXOTH:
                self.other_exec.set(True)
            
            self.log_message(f"Permissões lidas para: {path}", "INFO")
        except Exception as e:
            self.log_message(f"Erro ao ler permissões: {str(e)}", "ALERT")
    
    def apply_permissions(self):
        path = self.path_entry.get()
        if not path:
            self.log_message("Nenhum caminho especificado", "WARNING")
            return
        
        try:
            mode = 0
            
            # Permissões do dono
            if self.owner_read.get():
                mode |= stat.S_IRUSR
            if self.owner_write.get():
                mode |= stat.S_IWUSR
            if self.owner_exec.get():
                mode |= stat.S_IXUSR
            
            # Permissões do grupo
            if self.group_read.get():
                mode |= stat.S_IRGRP
            if self.group_write.get():
                mode |= stat.S_IWGRP
            if self.group_exec.get():
                mode |= stat.S_IXGRP
            
            # Permissões públicas
            if self.other_read.get():
                mode |= stat.S_IROTH
            if self.other_write.get():
                mode |= stat.S_IWOTH
            if self.other_exec.get():
                mode |= stat.S_IXOTH
            
            os.chmod(path, mode)
            self.log_message(f"Permissões aplicadas com sucesso em: {path}", "INFO")
        except Exception as e:
            self.log_message(f"Erro ao aplicar permissões: {str(e)}", "ALERT")
    
    def add_directory(self):
        path = filedialog.askdirectory()
        if path and path not in self.monitored_paths:
            self.monitored_paths[path] = {
                'recursive': self.recursive_var.get(),
                'handler': AdvancedFileMonitor(self.log_message, self.alert_message)
            }
            self.update_file_tree()
            self.log_message(f"Diretório adicionado para monitoramento: {path}", "INFO")
    
    def remove_directory(self):
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        for item in selected_items:
            path = self.tree.item(item)['text']
            if path in self.monitored_paths:
                del self.monitored_paths[path]
                self.log_message(f"Diretório removido do monitoramento: {path}", "INFO")
        
        self.update_file_tree()
    
    def start_monitoring(self):
        if not self.monitored_paths:
            self.log_message("Nenhum diretório adicionado para monitoramento", "WARNING")
            return
        
        if self.monitoring:
            self.log_message("Monitoramento já está em execução", "INFO")
            return
        
        self.observer = Observer()
        for path, config in self.monitored_paths.items():
            self.observer.schedule(config['handler'], path, recursive=config['recursive'])
        
        self.observer.start()
        self.monitoring = True
        self.log_message("Monitoramento iniciado", "INFO")
    
    def stop_monitoring(self):
        if not self.monitoring or not self.observer:
            self.log_message("Monitoramento não está em execução", "WARNING")
            return
        
        self.observer.stop()
        self.observer.join()
        self.monitoring = False
        self.log_message("Monitoramento parado", "INFO")
    
    def update_file_tree(self):
        self.tree.delete(*self.tree.get_children())
        for path, config in self.monitored_paths.items():
            parent = self.tree.insert("", "end", text=path, open=False)
            
            if config['recursive']:
                for root, dirs, files in os.walk(path):
                    for name in dirs + files:
                        full_path = os.path.join(root, name)
                        self.add_file_to_tree(parent, full_path)
            else:
                for name in os.listdir(path):
                    full_path = os.path.join(path, name)
                    self.add_file_to_tree(parent, full_path)
    
    def add_file_to_tree(self, parent, path):
        try:
            st = os.stat(path)
            mode = st.st_mode
            size = st.st_size
            mtime = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            # Obter nome do proprietário (apenas para Unix)
            try:
                import pwd
                owner = pwd.getpwuid(st.st_uid).pw_name
            except:
                owner = str(st.st_uid)
            
            perms = (
                ('r' if mode & stat.S_IRUSR else '-') +
                ('w' if mode & stat.S_IWUSR else '-') +
                ('x' if mode & stat.S_IXUSR else '-') + ' ' +
                ('r' if mode & stat.S_IRGRP else '-') +
                ('w' if mode & stat.S_IWGRP else '-') +
                ('x' if mode & stat.S_IXGRP else '-') + ' ' +
                ('r' if mode & stat.S_IROTH else '-') +
                ('w' if mode & stat.S_IWOTH else '-') +
                ('x' if mode & stat.S_IXOTH else '-')
            )
            
            self.tree.insert(parent, "end", text=path, values=(perms, self.format_size(size), mtime, owner))
        except Exception as e:
            self.log_message(f"Erro ao adicionar arquivo à árvore: {str(e)}", "WARNING")
    
    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def scan_vulnerabilities(self):
        self.log_message("Iniciando varredura de vulnerabilidades...", "INFO")
        vulnerabilities_found = 0
        
        for path, config in self.monitored_paths.items():
            for root, dirs, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    try:
                        st = os.stat(full_path)
                        
                        # Verificar permissões perigosas
                        if st.st_mode & stat.S_IWOTH:  # Escrita pública
                            self.log_message(f"VULNERABILIDADE: Arquivo com escrita pública: {full_path}", "ALERT")
                            vulnerabilities_found += 1
                        
                        # Verificar arquivos executáveis em locais suspeitos
                        if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                            if '/tmp/' in full_path or '/var/tmp/' in full_path:
                                self.log_message(f"VULNERABILIDADE: Executável em diretório temporário: {full_path}", "ALERT")
                                vulnerabilities_found += 1
                        
                        # Verificar arquivos ocultos
                        if file.startswith('.'):
                            self.log_message(f"AVISO: Arquivo oculto encontrado: {full_path}", "WARNING")
                    
                    except Exception as e:
                        self.log_message(f"Erro ao verificar {full_path}: {str(e)}", "WARNING")
        
        if vulnerabilities_found == 0:
            self.log_message("Nenhuma vulnerabilidade encontrada", "INFO")
        else:
            self.log_message(f"Total de vulnerabilidades encontradas: {vulnerabilities_found}", "ALERT")
    
    def audit_permissions(self):
        self.log_message("Iniciando auditoria de permissões...", "INFO")
        weak_permissions = 0
        
        for path, config in self.monitored_paths.items():
            for root, dirs, files in os.walk(path):
                for name in dirs + files:
                    full_path = os.path.join(root, name)
                    try:
                        st = os.stat(full_path)
                        
                        # Verificar diretórios com permissão de escrita pública
                        if os.path.isdir(full_path) and st.st_mode & stat.S_IWOTH:
                            self.log_message(f"PERIGO: Diretório com escrita pública: {full_path}", "ALERT")
                            weak_permissions += 1
                        
                        # Verificar arquivos com permissão de escrita pública
                        if os.path.isfile(full_path) and st.st_mode & stat.S_IWOTH:
                            self.log_message(f"PERIGO: Arquivo com escrita pública: {full_path}", "ALERT")
                            weak_permissions += 1
                        
                        # Verificar arquivos executáveis com escrita
                        if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                            if st.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
                                self.log_message(f"PERIGO: Executável com permissão de escrita: {full_path}", "ALERT")
                                weak_permissions += 1
                    
                    except Exception as e:
                        self.log_message(f"Erro ao auditar {full_path}: {str(e)}", "WARNING")
        
        if weak_permissions == 0:
            self.log_message("Nenhuma permissão fraca encontrada", "INFO")
        else:
            self.log_message(f"Total de permissões fracas encontradas: {weak_permissions}", "ALERT")
    
    def check_integrity(self):
        self.log_message("Iniciando verificação de integridade...", "INFO")
        changed_files = 0
        
        for path, config in self.monitored_paths.items():
            file_handler = config['handler']
            for root, dirs, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    try:
                        current_hash = file_handler.calculate_hash(full_path)
                        
                        if full_path in file_handler.checksums:
                            if current_hash != file_handler.checksums[full_path]:
                                self.log_message(f"ALERTA: Arquivo modificado: {full_path}", "ALERT")
                                changed_files += 1
                        else:
                            file_handler.checksums[full_path] = current_hash
                            self.log_message(f"Hash calculado para: {full_path}", "INFO")
                    
                    except Exception as e:
                        self.log_message(f"Erro ao verificar integridade de {full_path}: {str(e)}", "WARNING")
        
        if changed_files == 0:
            self.log_message("Nenhuma alteração não autorizada detectada", "INFO")
        else:
            self.log_message(f"Total de arquivos alterados: {changed_files}", "ALERT")
    
    def log_message(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted_message = f"[{timestamp}] [{level}] {message}\n"
        
        self.file_queue.put(("LOG", formatted_message, level))
    
    def alert_message(self, message):
        self.file_queue.put(("ALERT", message))
    
    def process_events(self):
        try:
            while True:
                item = self.file_queue.get_nowait()
                if item[0] == "LOG":
                    message, level = item[1], item[2]
                    self.log_text.insert(END, message, level)
                    self.log_text.see(END)
                elif item[0] == "ALERT":
                    message = item[1]
                    self.log_text.insert(END, f"[ALERTA] {message}\n", "ALERT")
                    self.log_text.see(END)
                    # Mostrar popup para alertas importantes
                    if "ALERTA" in message or "PERIGO" in message or "VULNERABILIDADE" in message:
                        self.root.bell()  # Beep sonoro
                        messagebox.showwarning("Alerta de Segurança", message)
        except queue.Empty:
            pass
        
        self.root.after(100, self.process_events)
    
    def on_close(self):
        self.stop_monitoring()
        self.root.destroy()

if __name__ == "__main__":
    root = Tk()
    app = PermissionManagerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
