import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from base_tool import AdvancedToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR, TEXT_COLOR
import ast
import os
import re
import json
import hashlib
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from difflib import SequenceMatcher
from collections import defaultdict

TAB_NAME = "Code Clone Detector"

class CodeCloneDetector:
    """Core code clone detection engine supporting multiple programming languages"""
    
    def __init__(self):
        self.reset_metrics()
        
        # Clone detection thresholds
        self.similarity_thresholds = {
            'exact': 1.0,           # 100% identical
            'near_exact': 0.95,     # 95% similar
            'high': 0.85,           # 85% similar
            'moderate': 0.70,       # 70% similar
            'low': 0.50             # 50% similar
        }
        
        # Minimum clone size (lines)
        self.min_clone_size = 5
        
        # File extensions to analyze
        self.supported_extensions = ['.py', '.js', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs']
    
    def reset_metrics(self):
        """Reset all metrics for new analysis"""
        self.clone_groups = []
        self.file_clones = {}
        self.similarity_matrix = {}
        self.total_files_analyzed = 0
        self.total_lines_analyzed = 0
        self.total_clones_found = 0
        
    def analyze_file(self, file_path):
        """Analyze a single file for internal clones"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.py':
                return self._analyze_python_file(file_path, content, lines)
            else:
                return self._analyze_generic_file(file_path, content, lines)
                
        except Exception as e:
            raise Exception(f"Error analyzing file {file_path}: {e}")
    
    def analyze_directory(self, directory_path, include_subdirs=True):
        """Analyze all files in a directory for clones"""
        file_contents = {}
        file_blocks = {}
        
        # Collect all files
        for root, dirs, files in os.walk(directory_path):
            if not include_subdirs:
                dirs.clear()  # Don't recurse into subdirectories
            
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', '.vscode', '.idea', 'build', 'dist']]
            
            for file in files:
                if any(file.lower().endswith(ext) for ext in self.supported_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        file_contents[file_path] = content
                        file_blocks[file_path] = self._extract_code_blocks(content, file_path)
                        
                    except Exception as e:
                        print(f"Error reading {file_path}: {e}")
                        continue
        
        self.total_files_analyzed = len(file_contents)
        self.total_lines_analyzed = sum(len(content.split('\n')) for content in file_contents.values())
        
        # Find clones across files
        clone_groups = self._find_cross_file_clones(file_blocks)
        
        # Find clones within files
        for file_path, content in file_contents.items():
            internal_clones = self._find_internal_clones(file_path, content)
            if internal_clones:
                clone_groups.extend(internal_clones)
        
        self.clone_groups = clone_groups
        self.total_clones_found = len(clone_groups)
        
        return self._generate_directory_results(directory_path, file_contents, clone_groups)
    
    def _analyze_python_file(self, file_path, content, lines):
        """Analyze Python file using AST parsing for better accuracy"""
        try:
            tree = ast.parse(content, filename=file_path)
            
            # Extract functions and classes as potential clone candidates
            code_blocks = []
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_lines = self._extract_node_lines(node, lines)
                    if len(func_lines) >= self.min_clone_size:
                        code_blocks.append({
                            'type': 'function',
                            'name': node.name,
                            'start_line': node.lineno,
                            'end_line': getattr(node, 'end_lineno', node.lineno + len(func_lines)),
                            'lines': func_lines,
                            'normalized': self._normalize_code_block(func_lines),
                            'hash': self._calculate_block_hash(func_lines)
                        })
                
                elif isinstance(node, ast.ClassDef):
                    class_lines = self._extract_node_lines(node, lines)
                    if len(class_lines) >= self.min_clone_size:
                        code_blocks.append({
                            'type': 'class',
                            'name': node.name,
                            'start_line': node.lineno,
                            'end_line': getattr(node, 'end_lineno', node.lineno + len(class_lines)),
                            'lines': class_lines,
                            'normalized': self._normalize_code_block(class_lines),
                            'hash': self._calculate_block_hash(class_lines)
                        })
            
            # Find clones within the file
            internal_clones = self._find_clones_in_blocks(file_path, code_blocks)
            
            return {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'total_lines': len(lines),
                'code_blocks': len(code_blocks),
                'internal_clones': len(internal_clones),
                'clone_groups': internal_clones,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except SyntaxError as e:
            return self._analyze_generic_file(file_path, content, lines)
    
    def _analyze_generic_file(self, file_path, content, lines):
        """Generic analysis for non-Python files using line-based approach"""
        # Extract code blocks using sliding window approach
        code_blocks = []
        
        for i in range(len(lines) - self.min_clone_size + 1):
            block_lines = lines[i:i + self.min_clone_size]
            
            # Skip blocks that are mostly empty or comments
            non_empty_lines = [line for line in block_lines if line.strip() and not self._is_comment_line(line)]
            if len(non_empty_lines) < self.min_clone_size // 2:
                continue
            
            code_blocks.append({
                'type': 'block',
                'name': f'Block_{i+1}',
                'start_line': i + 1,
                'end_line': i + self.min_clone_size,
                'lines': block_lines,
                'normalized': self._normalize_code_block(block_lines),
                'hash': self._calculate_block_hash(block_lines)
            })
        
        # Find clones within the file
        internal_clones = self._find_clones_in_blocks(file_path, code_blocks)
        
        return {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'total_lines': len(lines),
            'code_blocks': len(code_blocks),
            'internal_clones': len(internal_clones),
            'clone_groups': internal_clones,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _extract_code_blocks(self, content, file_path):
        """Extract code blocks from file content"""
        lines = content.split('\n')
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext == '.py':
            try:
                tree = ast.parse(content, filename=file_path)
                blocks = []
                
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        node_lines = self._extract_node_lines(node, lines)
                        if len(node_lines) >= self.min_clone_size:
                            blocks.append({
                                'file_path': file_path,
                                'type': 'function' if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else 'class',
                                'name': node.name,
                                'start_line': node.lineno,
                                'end_line': getattr(node, 'end_lineno', node.lineno + len(node_lines)),
                                'lines': node_lines,
                                'normalized': self._normalize_code_block(node_lines),
                                'hash': self._calculate_block_hash(node_lines)
                            })
                
                return blocks
                
            except SyntaxError:
                pass  # Fall back to generic approach
        
        # Generic sliding window approach
        blocks = []
        for i in range(len(lines) - self.min_clone_size + 1):
            block_lines = lines[i:i + self.min_clone_size]
            
            # Skip blocks that are mostly empty or comments
            non_empty_lines = [line for line in block_lines if line.strip() and not self._is_comment_line(line)]
            if len(non_empty_lines) < self.min_clone_size // 2:
                continue
            
            blocks.append({
                'file_path': file_path,
                'type': 'block',
                'name': f'Block_{i+1}',
                'start_line': i + 1,
                'end_line': i + self.min_clone_size,
                'lines': block_lines,
                'normalized': self._normalize_code_block(block_lines),
                'hash': self._calculate_block_hash(block_lines)
            })
        
        return blocks
    
    def _extract_node_lines(self, node, lines):
        """Extract lines of code for an AST node"""
        start_line = node.lineno - 1  # Convert to 0-based indexing
        
        if hasattr(node, 'end_lineno') and node.end_lineno:
            end_line = node.end_lineno
        else:
            # Estimate end line by finding next node or end of file
            end_line = len(lines)
            
        return lines[start_line:end_line]
    
    def _normalize_code_block(self, lines):
        """Normalize code block for better clone detection"""
        normalized = []
        
        for line in lines:
            # Remove leading/trailing whitespace
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or self._is_comment_line(line):
                continue
            
            # Normalize whitespace
            line = re.sub(r'\s+', ' ', line)
            
            # Remove string literals (replace with placeholder)
            line = re.sub(r'"[^"]*"', '"STRING"', line)
            line = re.sub(r"'[^']*'", "'STRING'", line)
            
            # Remove numeric literals (replace with placeholder)
            line = re.sub(r'\b\d+\.?\d*\b', 'NUMBER', line)
            
            # Normalize variable names (optional - can be too aggressive)
            # line = re.sub(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', 'VAR', line)
            
            normalized.append(line)
        
        return normalized
    
    def _calculate_block_hash(self, lines):
        """Calculate hash for a code block"""
        normalized = self._normalize_code_block(lines)
        content = '\n'.join(normalized)
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def _is_comment_line(self, line):
        """Check if a line is a comment"""
        stripped = line.strip()
        
        # Common comment patterns
        comment_patterns = [
            r'^\s*#',           # Python, Ruby, Shell
            r'^\s*//',          # C++, Java, JavaScript
            r'^\s*/\*',         # C, Java, JavaScript (start)
            r'^\s*\*',          # C, Java, JavaScript (middle)
            r'^\s*\*/',         # C, Java, JavaScript (end)
            r'^\s*<!--',        # HTML, XML
            r'^\s*%',           # LaTeX, MATLAB
            r'^\s*;',           # Assembly, Lisp
        ]
        
        return any(re.match(pattern, stripped) for pattern in comment_patterns)
    
    def _find_cross_file_clones(self, file_blocks):
        """Find clones across different files"""
        clone_groups = []
        
        # Group blocks by hash for exact matches
        hash_groups = defaultdict(list)
        for file_path, blocks in file_blocks.items():
            for block in blocks:
                hash_groups[block['hash']].append(block)
        
        # Find exact clones
        for hash_value, blocks in hash_groups.items():
            if len(blocks) > 1:
                clone_groups.append({
                    'type': 'exact',
                    'similarity': 1.0,
                    'blocks': blocks,
                    'clone_size': len(blocks[0]['lines']),
                    'refactoring_opportunity': self._generate_refactoring_suggestion(blocks, 1.0)
                })
        
        # Find near-duplicate clones using similarity comparison
        all_blocks = []
        for blocks in file_blocks.values():
            all_blocks.extend(blocks)
        
        # Compare all pairs of blocks for similarity
        for i in range(len(all_blocks)):
            for j in range(i + 1, len(all_blocks)):
                block1, block2 = all_blocks[i], all_blocks[j]
                
                # Skip if same file and overlapping blocks
                if (block1['file_path'] == block2['file_path'] and 
                    self._blocks_overlap(block1, block2)):
                    continue
                
                # Skip if already found as exact clone
                if block1['hash'] == block2['hash']:
                    continue
                
                similarity = self._calculate_similarity(block1['normalized'], block2['normalized'])
                
                if similarity >= self.similarity_thresholds['moderate']:
                    clone_type = self._classify_similarity(similarity)
                    
                    clone_groups.append({
                        'type': clone_type,
                        'similarity': similarity,
                        'blocks': [block1, block2],
                        'clone_size': min(len(block1['lines']), len(block2['lines'])),
                        'refactoring_opportunity': self._generate_refactoring_suggestion([block1, block2], similarity)
                    })
        
        return clone_groups
    
    def _find_internal_clones(self, file_path, content):
        """Find clones within a single file"""
        lines = content.split('\n')
        blocks = self._extract_code_blocks(content, file_path)
        
        return self._find_clones_in_blocks(file_path, blocks)
    
    def _find_clones_in_blocks(self, file_path, blocks):
        """Find clones within a list of blocks"""
        clone_groups = []
        
        # Group by hash for exact matches
        hash_groups = defaultdict(list)
        for block in blocks:
            hash_groups[block['hash']].append(block)
        
        # Find exact clones
        for hash_value, block_list in hash_groups.items():
            if len(block_list) > 1:
                clone_groups.append({
                    'type': 'exact',
                    'similarity': 1.0,
                    'blocks': block_list,
                    'clone_size': len(block_list[0]['lines']),
                    'refactoring_opportunity': self._generate_refactoring_suggestion(block_list, 1.0)
                })
        
        # Find near-duplicate clones
        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                block1, block2 = blocks[i], blocks[j]
                
                # Skip if overlapping blocks
                if self._blocks_overlap(block1, block2):
                    continue
                
                # Skip if already found as exact clone
                if block1['hash'] == block2['hash']:
                    continue
                
                similarity = self._calculate_similarity(block1['normalized'], block2['normalized'])
                
                if similarity >= self.similarity_thresholds['moderate']:
                    clone_type = self._classify_similarity(similarity)
                    
                    clone_groups.append({
                        'type': clone_type,
                        'similarity': similarity,
                        'blocks': [block1, block2],
                        'clone_size': min(len(block1['lines']), len(block2['lines'])),
                        'refactoring_opportunity': self._generate_refactoring_suggestion([block1, block2], similarity)
                    })
        
        return clone_groups
    
    def _blocks_overlap(self, block1, block2):
        """Check if two blocks overlap in the same file"""
        if block1.get('file_path') != block2.get('file_path'):
            return False
        
        start1, end1 = block1['start_line'], block1['end_line']
        start2, end2 = block2['start_line'], block2['end_line']
        
        return not (end1 < start2 or end2 < start1)
    
    def _calculate_similarity(self, lines1, lines2):
        """Calculate similarity between two code blocks"""
        if not lines1 or not lines2:
            return 0.0
        
        # Use sequence matcher for line-by-line comparison
        matcher = SequenceMatcher(None, lines1, lines2)
        return matcher.ratio()
    
    def _classify_similarity(self, similarity):
        """Classify similarity level"""
        if similarity >= self.similarity_thresholds['exact']:
            return 'exact'
        elif similarity >= self.similarity_thresholds['near_exact']:
            return 'near_exact'
        elif similarity >= self.similarity_thresholds['high']:
            return 'high'
        elif similarity >= self.similarity_thresholds['moderate']:
            return 'moderate'
        else:
            return 'low'
    
    def _generate_refactoring_suggestion(self, blocks, similarity):
        """Generate refactoring suggestions for clone groups"""
        if len(blocks) < 2:
            return {}
        
        # Determine refactoring strategy based on similarity and context
        if similarity >= self.similarity_thresholds['near_exact']:
            strategy = "extract_method"
            description = "Extract identical code into a shared method/function"
            effort = "Low"
            impact = "High"
        elif similarity >= self.similarity_thresholds['high']:
            strategy = "parameterize_method"
            description = "Extract similar code and parameterize differences"
            effort = "Medium"
            impact = "High"
        else:
            strategy = "template_method"
            description = "Use template method pattern to share common structure"
            effort = "High"
            impact = "Medium"
        
        # Check if clones are in same file or different files
        files = set(block.get('file_path', '') for block in blocks)
        cross_file = len(files) > 1
        
        steps = []
        if strategy == "extract_method":
            if cross_file:
                steps = [
                    "1. Create a new utility module or class",
                    "2. Extract the common code into a new method",
                    "3. Replace all clone instances with calls to the new method",
                    "4. Add appropriate parameters for any variations",
                    "5. Update imports in affected files",
                    "6. Test all affected functionality"
                ]
            else:
                steps = [
                    "1. Extract the duplicated code into a new method",
                    "2. Replace all clone instances with calls to the new method",
                    "3. Add parameters for any variations",
                    "4. Test the refactored code"
                ]
        
        elif strategy == "parameterize_method":
            steps = [
                "1. Identify the differences between similar code blocks",
                "2. Extract common code into a new method",
                "3. Add parameters to handle the differences",
                "4. Replace all similar blocks with calls to the parameterized method",
                "5. Test with all parameter combinations"
            ]
        
        else:  # template_method
            steps = [
                "1. Identify the common algorithm structure",
                "2. Create a base class with the template method",
                "3. Extract variable parts into abstract methods",
                "4. Create concrete implementations for each variation",
                "5. Refactor existing code to use the new hierarchy"
            ]
        
        return {
            'strategy': strategy,
            'description': description,
            'effort': effort,
            'impact': impact,
            'cross_file': cross_file,
            'steps': steps,
            'estimated_time_hours': self._estimate_refactoring_time(strategy, len(blocks), cross_file),
            'priority': self._calculate_priority(similarity, len(blocks), cross_file)
        }
    
    def _estimate_refactoring_time(self, strategy, clone_count, cross_file):
        """Estimate time required for refactoring"""
        base_times = {
            'extract_method': 2.0,
            'parameterize_method': 4.0,
            'template_method': 8.0
        }
        
        base_time = base_times.get(strategy, 2.0)
        
        # Adjust for number of clones
        time_multiplier = 1 + (clone_count - 2) * 0.3
        
        # Adjust for cross-file complexity
        if cross_file:
            time_multiplier *= 1.5
        
        return round(base_time * time_multiplier, 1)
    
    def _calculate_priority(self, similarity, clone_count, cross_file):
        """Calculate refactoring priority"""
        score = 0
        
        # Higher similarity = higher priority
        if similarity >= 0.95:
            score += 3
        elif similarity >= 0.85:
            score += 2
        else:
            score += 1
        
        # More clones = higher priority
        if clone_count >= 5:
            score += 3
        elif clone_count >= 3:
            score += 2
        else:
            score += 1
        
        # Cross-file clones are higher priority
        if cross_file:
            score += 1
        
        if score >= 6:
            return "High"
        elif score >= 4:
            return "Medium"
        else:
            return "Low"
    
    def _generate_directory_results(self, directory_path, file_contents, clone_groups):
        """Generate comprehensive results for directory analysis"""
        # Calculate statistics
        total_clones = len(clone_groups)
        exact_clones = len([g for g in clone_groups if g['type'] == 'exact'])
        near_clones = len([g for g in clone_groups if g['type'] in ['near_exact', 'high']])
        
        # Calculate duplication percentage
        total_duplicated_lines = sum(
            len(group['blocks']) * group['clone_size'] 
            for group in clone_groups
        )
        duplication_percentage = (total_duplicated_lines / max(self.total_lines_analyzed, 1)) * 100
        
        # Group clones by type
        clones_by_type = defaultdict(int)
        for group in clone_groups:
            clones_by_type[group['type']] += 1
        
        # Find most problematic files
        file_clone_counts = defaultdict(int)
        for group in clone_groups:
            for block in group['blocks']:
                file_path = block.get('file_path', '')
                if file_path:
                    file_clone_counts[file_path] += 1
        
        most_problematic_files = sorted(
            file_clone_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return {
            'directory_path': directory_path,
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_files_analyzed': self.total_files_analyzed,
                'total_lines_analyzed': self.total_lines_analyzed,
                'total_clones_found': total_clones,
                'exact_clones': exact_clones,
                'near_clones': near_clones,
                'duplication_percentage': round(duplication_percentage, 2),
                'total_duplicated_lines': total_duplicated_lines,
                'clones_by_type': dict(clones_by_type)
            },
            'clone_groups': clone_groups,
            'most_problematic_files': most_problematic_files,
            'refactoring_opportunities': self._summarize_refactoring_opportunities(clone_groups)
        }
    
    def _summarize_refactoring_opportunities(self, clone_groups):
        """Summarize refactoring opportunities"""
        opportunities = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'total_estimated_hours': 0
        }
        
        for group in clone_groups:
            refactoring = group.get('refactoring_opportunity', {})
            priority = refactoring.get('priority', 'Low')
            estimated_hours = refactoring.get('estimated_time_hours', 0)
            
            opportunity = {
                'description': refactoring.get('description', ''),
                'strategy': refactoring.get('strategy', ''),
                'clone_count': len(group['blocks']),
                'similarity': group['similarity'],
                'estimated_hours': estimated_hours,
                'files_affected': list(set(block.get('file_path', '') for block in group['blocks']))
            }
            
            if priority == 'High':
                opportunities['high_priority'].append(opportunity)
            elif priority == 'Medium':
                opportunities['medium_priority'].append(opportunity)
            else:
                opportunities['low_priority'].append(opportunity)
            
            opportunities['total_estimated_hours'] += estimated_hours
        
        return opportunities


class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Code Clone Detector',
            'tool_id': 'code_clone_detector',
            'category': 'Code Analysis'
        })
        
        self.detector = CodeCloneDetector()
        self.current_results = None
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Setup advanced UI components
        self.setup_advanced_ui()
        
        # Main container
        main_container = tk.Frame(self, bg=BG_COLOR)
        main_container.pack(fill="both", expand=True, before=self.results_notebook)
        
        # Left panel for controls
        left_panel = tk.Frame(main_container, bg=PANEL_COLOR, width=350)
        left_panel.pack(side="left", fill="y", padx=5, pady=5)
        left_panel.pack_propagate(False)
        
        # Right panel for visualization
        right_panel = tk.Frame(main_container, bg=BG_COLOR)
        right_panel.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        self.setup_control_panel(left_panel)
        self.setup_visualization_panel(right_panel)
    
    def setup_control_panel(self, parent):
        """Setup the control panel with analysis options"""
        # Title
        title_label = tk.Label(parent, text="🔍 Code Clone Detector", 
                              bg=PANEL_COLOR, fg=TEXT_COLOR, font=("Consolas", 14, "bold"))
        title_label.pack(pady=10)
        
        # Target selection
        target_frame = tk.Frame(parent, bg=PANEL_COLOR)
        target_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(target_frame, text="Analysis Target:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.target_path_var = tk.StringVar()
        target_entry = tk.Entry(target_frame, textvariable=self.target_path_var, 
                               bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        target_entry.pack(fill="x", pady=2)
        
        button_frame = tk.Frame(target_frame, bg=PANEL_COLOR)
        button_frame.pack(fill="x", pady=2)
        
        file_btn = tk.Button(button_frame, text="Select File", command=self.browse_file)
        style_button(file_btn)
        file_btn.pack(side="left", padx=2, fill="x", expand=True)
        
        dir_btn = tk.Button(button_frame, text="Select Directory", command=self.browse_directory)
        style_button(dir_btn)
        dir_btn.pack(side="right", padx=2, fill="x", expand=True)
        
        # Detection options
        options_frame = tk.Frame(parent, bg=PANEL_COLOR)
        options_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(options_frame, text="Detection Options:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.include_subdirs_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Include Subdirectories", variable=self.include_subdirs_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        self.detect_exact_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Detect Exact Clones", variable=self.detect_exact_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        self.detect_near_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Detect Near-Duplicate Clones", variable=self.detect_near_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        self.generate_suggestions_var = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Generate Refactoring Suggestions", variable=self.generate_suggestions_var,
                      bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        # Similarity thresholds
        threshold_frame = tk.Frame(parent, bg=PANEL_COLOR)
        threshold_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(threshold_frame, text="Similarity Thresholds:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        # Minimum similarity
        sim_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        sim_frame.pack(fill="x", pady=1)
        tk.Label(sim_frame, text="Min Similarity:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=12).pack(side="left")
        self.min_similarity = tk.Scale(sim_frame, from_=0.5, to=1.0, resolution=0.05, 
                                      orient="horizontal", bg=PANEL_COLOR, fg=TEXT_COLOR,
                                      highlightbackground=PANEL_COLOR)
        self.min_similarity.set(0.70)
        self.min_similarity.pack(side="left", fill="x", expand=True)
        
        # Minimum clone size
        size_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        size_frame.pack(fill="x", pady=1)
        tk.Label(size_frame, text="Min Clone Size:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=12).pack(side="left")
        self.min_clone_size = tk.Spinbox(size_frame, from_=3, to=50, value=5, width=10,
                                        bg="#111111", fg=TEXT_COLOR)
        self.min_clone_size.pack(side="left")
        
        # Action buttons
        action_frame = tk.Frame(parent, bg=PANEL_COLOR)
        action_frame.pack(fill="x", padx=10, pady=20)
        
        detect_btn = tk.Button(action_frame, text="🔍 Detect Clones", command=self.detect_clones)
        style_button(detect_btn)
        detect_btn.pack(fill="x", pady=2)
        
        suggestions_btn = tk.Button(action_frame, text="💡 Generate Suggestions", command=self.generate_suggestions)
        style_button(suggestions_btn)
        suggestions_btn.pack(fill="x", pady=2)
        
        clear_btn = tk.Button(action_frame, text="🗑 Clear Results", command=self.clear_results)
        style_button(clear_btn)
        clear_btn.pack(fill="x", pady=2)
    
    def setup_visualization_panel(self, parent):
        """Setup the visualization panel for clone analysis"""
        # Visualization title
        viz_title = tk.Label(parent, text="📊 Clone Analysis Visualization", 
                            bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 12, "bold"))
        viz_title.pack(pady=10)
        
        # Matplotlib figure frame
        self.viz_frame = tk.Frame(parent, bg=BG_COLOR)
        self.viz_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Initial placeholder
        placeholder_label = tk.Label(self.viz_frame, text="Analyze code to see clone detection visualization",
                                    bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        placeholder_label.pack(expand=True)
    
    def browse_file(self):
        """Browse and select a file for analysis"""
        file_path = filedialog.askopenfilename(
            title="Select Code File for Clone Detection",
            filetypes=[
                ("Python Files", "*.py"),
                ("JavaScript Files", "*.js"),
                ("Java Files", "*.java"),
                ("C++ Files", "*.cpp;*.cc;*.cxx"),
                ("C Files", "*.c"),
                ("C# Files", "*.cs"),
                ("PHP Files", "*.php"),
                ("Ruby Files", "*.rb"),
                ("Go Files", "*.go"),
                ("Rust Files", "*.rs"),
                ("All Code Files", "*.py;*.js;*.java;*.cpp;*.c;*.cs;*.php;*.rb;*.go;*.rs"),
                ("All Files", "*.*")
            ]
        )
        
        if file_path:
            self.target_path_var.set(file_path)
    
    def browse_directory(self):
        """Browse and select a directory for analysis"""
        directory = filedialog.askdirectory(title="Select Directory for Clone Detection")
        
        if directory:
            self.target_path_var.set(directory)
    
    def detect_clones(self):
        """Detect code clones in the selected target"""
        target_path = self.target_path_var.get().strip()
        
        if not target_path:
            messagebox.showerror("Error", "Please select a file or directory to analyze.")
            return
        
        if not os.path.exists(target_path):
            messagebox.showerror("Error", "Selected path does not exist.")
            return
        
        try:
            # Update detector settings
            self.detector.similarity_thresholds['moderate'] = self.min_similarity.get()
            self.detector.min_clone_size = int(self.min_clone_size.get())
            
            self.update_progress(10, "Starting clone detection...")
            
            if os.path.isfile(target_path):
                # Single file analysis
                self.update_progress(30, "Analyzing file for internal clones...")
                results = self.detector.analyze_file(target_path)
                self.current_results = results
            else:
                # Directory analysis
                self.update_progress(30, "Scanning directory for clones...")
                include_subdirs = self.include_subdirs_var.get()
                results = self.detector.analyze_directory(target_path, include_subdirs)
                self.current_results = results
            
            self.update_progress(70, "Generating reports...")
            
            # Update results display
            self.update_results_display()
            
            # Generate visualization
            self.generate_clone_visualization()
            
            self.update_progress(100, "Clone detection complete!")
            
            # Save results to database
            self.save_analysis_result(
                analysis_id=f"clone_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                input_data={'target_path': target_path},
                results_summary=self.current_results.get('summary', self.current_results),
                detailed_findings=self.current_results.get('clone_groups', []),
                recommendations=self.generate_recommendations(),
                metrics=self._extract_key_metrics()
            )
            
            if 'summary' in self.current_results:
                summary = self.current_results['summary']
                messagebox.showinfo("Clone Detection Complete", 
                                  f"Files Analyzed: {summary.get('total_files_analyzed', 1)}\n"
                                  f"Clones Found: {summary.get('total_clones_found', 0)}\n"
                                  f"Duplication: {summary.get('duplication_percentage', 0):.1f}%")
            else:
                messagebox.showinfo("Clone Detection Complete", 
                                  f"Internal Clones Found: {self.current_results.get('internal_clones', 0)}")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            messagebox.showerror("Detection Error", f"Failed to detect clones:\n{str(e)}")    

    def generate_suggestions(self):
        """Generate detailed refactoring suggestions for detected clones"""
        if not self.current_results:
            messagebox.showwarning("No Data", "Please run clone detection first.")
            return
        
        try:
            suggestions = self._create_refactoring_suggestions()
            
            suggestions_text = f"""Code Clone Refactoring Suggestions
{'=' * 50}

Summary:
• Total Clone Groups: {suggestions['summary']['total_groups']}
• High Priority Opportunities: {suggestions['summary']['high_priority']}
• Estimated Total Effort: {suggestions['summary']['total_hours']:.1f} hours

High Priority Refactoring Opportunities:
{'-' * 50}
"""
            
            for i, opp in enumerate(suggestions['high_priority'][:5], 1):
                suggestions_text += f"{i}. {opp['description']}\n"
                suggestions_text += f"   Strategy: {opp['strategy']}\n"
                suggestions_text += f"   Files: {len(opp['files_affected'])}, Clones: {opp['clone_count']}\n"
                suggestions_text += f"   Similarity: {opp['similarity']:.1%}, Effort: {opp['estimated_hours']:.1f}h\n\n"
            
            suggestions_text += f"""
Medium Priority Opportunities:
{'-' * 50}
"""
            
            for i, opp in enumerate(suggestions['medium_priority'][:3], 1):
                suggestions_text += f"{i}. {opp['description']}\n"
                suggestions_text += f"   Strategy: {opp['strategy']}, Effort: {opp['estimated_hours']:.1f}h\n\n"
            
            suggestions_text += f"""
Implementation Recommendations:
• Start with exact clones (100% similarity) for quick wins
• Focus on cross-file clones to reduce maintenance burden
• Use automated refactoring tools where available
• Ensure comprehensive test coverage before refactoring
• Consider creating utility libraries for commonly duplicated patterns
"""
            
            # Update results tab with suggestions
            self.update_results_tab("Analysis", suggestions_text)
            
            messagebox.showinfo("Suggestions Generated", 
                              f"Generated {len(suggestions['high_priority'])} high-priority suggestions")
            
        except Exception as e:
            messagebox.showerror("Suggestion Error", f"Failed to generate suggestions:\n{str(e)}")
    
    def clear_results(self):
        """Clear all results and reset the interface"""
        self.current_results = None
        self.detector.reset_metrics()
        
        # Clear results tabs
        if hasattr(self, 'tab_frames'):
            for tab_name, text_widget in self.tab_frames.items():
                text_widget.delete(1.0, tk.END)
        
        # Clear visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        placeholder_label = tk.Label(self.viz_frame, text="Analyze code to see clone detection visualization",
                                    bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        placeholder_label.pack(expand=True)
        
        # Reset progress
        self.update_progress(0, "Ready")
    
    def update_results_display(self):
        """Update the results tabs with clone detection data"""
        if not self.current_results:
            return
        
        if 'summary' in self.current_results:
            # Directory analysis results
            self._update_directory_results()
        else:
            # Single file analysis results
            self._update_file_results()
    
    def _update_directory_results(self):
        """Update results display for directory analysis"""
        results = self.current_results
        summary = results['summary']
        
        # Summary tab
        summary_text = f"""Code Clone Detection Summary
{'=' * 50}

Analysis Overview:
• Directory: {results['directory_path']}
• Files Analyzed: {summary['total_files_analyzed']}
• Total Lines: {summary['total_lines_analyzed']:,}
• Analysis Time: {results['analysis_timestamp']}

Clone Detection Results:
• Total Clone Groups: {summary['total_clones_found']}
• Exact Clones: {summary['exact_clones']}
• Near-Duplicate Clones: {summary['near_clones']}
• Duplication Percentage: {summary['duplication_percentage']:.2f}%
• Total Duplicated Lines: {summary['total_duplicated_lines']:,}

Clones by Type:
"""
        
        clones_by_type = summary.get('clones_by_type', {})
        for clone_type, count in clones_by_type.items():
            if count > 0:
                summary_text += f"• {clone_type.replace('_', ' ').title()}: {count}\n"
        
        summary_text += f"""
Most Problematic Files:
{'-' * 30}
"""
        
        for i, (file_path, clone_count) in enumerate(results.get('most_problematic_files', [])[:10], 1):
            file_name = os.path.basename(file_path)
            summary_text += f"{i}. {file_name} ({clone_count} clones)\n"
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab
        details_text = "Detailed Clone Analysis\n" + "=" * 50 + "\n\n"
        
        clone_groups = results.get('clone_groups', [])
        for i, group in enumerate(clone_groups[:20], 1):  # Show top 20 groups
            details_text += f"Clone Group {i}:\n"
            details_text += f"Type: {group['type']}, Similarity: {group['similarity']:.1%}\n"
            details_text += f"Clone Size: {group['clone_size']} lines\n"
            details_text += f"Blocks: {len(group['blocks'])}\n"
            
            for j, block in enumerate(group['blocks'], 1):
                file_name = os.path.basename(block.get('file_path', 'Unknown'))
                details_text += f"  {j}. {file_name} (Lines {block['start_line']}-{block['end_line']})\n"
            
            refactoring = group.get('refactoring_opportunity', {})
            if refactoring:
                details_text += f"Refactoring: {refactoring.get('strategy', 'N/A')} "
                details_text += f"(Priority: {refactoring.get('priority', 'N/A')}, "
                details_text += f"Effort: {refactoring.get('estimated_time_hours', 0):.1f}h)\n"
            
            details_text += "\n"
        
        self.update_results_tab("Details", details_text)
        
        # Raw Data tab
        raw_data = json.dumps(results, indent=2, default=str)
        self.update_results_tab("Raw Data", raw_data)
        
        # Set results data for export
        self.set_results_data(results)
    
    def _update_file_results(self):
        """Update results display for single file analysis"""
        results = self.current_results
        
        # Summary tab
        summary_text = f"""Single File Clone Analysis
{'=' * 50}

File Information:
• File: {results['file_name']}
• Path: {results['file_path']}
• Total Lines: {results['total_lines']}
• Code Blocks Analyzed: {results['code_blocks']}
• Analysis Time: {results['analysis_timestamp']}

Clone Detection Results:
• Internal Clone Groups: {results['internal_clones']}
"""
        
        clone_groups = results.get('clone_groups', [])
        if clone_groups:
            summary_text += f"\nClone Groups Found:\n{'-' * 20}\n"
            
            for i, group in enumerate(clone_groups, 1):
                summary_text += f"{i}. Type: {group['type']}, Similarity: {group['similarity']:.1%}\n"
                summary_text += f"   Blocks: {len(group['blocks'])}, Size: {group['clone_size']} lines\n"
                
                refactoring = group.get('refactoring_opportunity', {})
                if refactoring:
                    summary_text += f"   Refactoring: {refactoring.get('strategy', 'N/A')} "
                    summary_text += f"(Effort: {refactoring.get('estimated_time_hours', 0):.1f}h)\n"
                summary_text += "\n"
        else:
            summary_text += "\nNo internal clones detected in this file."
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab
        details_text = "Detailed Clone Information\n" + "=" * 50 + "\n\n"
        
        if clone_groups:
            for i, group in enumerate(clone_groups, 1):
                details_text += f"Clone Group {i}:\n"
                details_text += f"Type: {group['type']}\n"
                details_text += f"Similarity: {group['similarity']:.1%}\n"
                details_text += f"Clone Size: {group['clone_size']} lines\n\n"
                
                for j, block in enumerate(group['blocks'], 1):
                    details_text += f"Block {j}:\n"
                    details_text += f"  Type: {block.get('type', 'N/A')}\n"
                    details_text += f"  Name: {block.get('name', 'N/A')}\n"
                    details_text += f"  Lines: {block['start_line']}-{block['end_line']}\n"
                    details_text += f"  Hash: {block.get('hash', 'N/A')[:16]}...\n\n"
                
                refactoring = group.get('refactoring_opportunity', {})
                if refactoring:
                    details_text += f"Refactoring Opportunity:\n"
                    details_text += f"  Strategy: {refactoring.get('strategy', 'N/A')}\n"
                    details_text += f"  Description: {refactoring.get('description', 'N/A')}\n"
                    details_text += f"  Priority: {refactoring.get('priority', 'N/A')}\n"
                    details_text += f"  Estimated Time: {refactoring.get('estimated_time_hours', 0):.1f} hours\n"
                    
                    steps = refactoring.get('steps', [])
                    if steps:
                        details_text += f"  Steps:\n"
                        for step in steps:
                            details_text += f"    {step}\n"
                
                details_text += "\n" + "-" * 50 + "\n\n"
        else:
            details_text += "No clones detected in this file.\n"
        
        self.update_results_tab("Details", details_text)
        
        # Raw Data tab
        raw_data = json.dumps(results, indent=2, default=str)
        self.update_results_tab("Raw Data", raw_data)
        
        # Set results data for export
        self.set_results_data(results)
    
    def generate_clone_visualization(self):
        """Generate visual representation of clone detection results"""
        if not self.current_results:
            return
        
        # Clear existing visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        try:
            # Create matplotlib figure
            fig, axes = plt.subplots(2, 2, figsize=(12, 10))
            fig.patch.set_facecolor('#1a1a1a')
            
            if 'summary' in self.current_results:
                self._create_directory_visualization(axes)
            else:
                self._create_file_visualization(axes)
            
            # Embed plot in tkinter
            canvas = FigureCanvasTkAgg(fig, self.viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
            
        except Exception as e:
            error_label = tk.Label(self.viz_frame, text=f"Visualization Error: {str(e)}",
                                 bg=BG_COLOR, fg="#FF6B6B", font=("Consolas", 10))
            error_label.pack(expand=True)
    
    def _create_directory_visualization(self, axes):
        """Create visualization for directory analysis results"""
        results = self.current_results
        summary = results['summary']
        
        # Clone type distribution (pie chart)
        ax1 = axes[0, 0]
        clones_by_type = summary.get('clones_by_type', {})
        if clones_by_type:
            labels = [t.replace('_', ' ').title() for t in clones_by_type.keys()]
            sizes = list(clones_by_type.values())
            colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7']
            
            wedges, texts, autotexts = ax1.pie(sizes, labels=labels, colors=colors[:len(labels)], 
                                              autopct='%1.1f%%', startangle=90)
            ax1.set_title('Clone Distribution by Type', color='white', fontweight='bold')
            
            # Style the text
            for text in texts + autotexts:
                text.set_color('white')
        else:
            ax1.text(0.5, 0.5, 'No clones detected', ha='center', va='center', 
                    transform=ax1.transAxes, color='white')
        
        ax1.set_facecolor('#2a2a2a')
        
        # Files with most clones (bar chart)
        ax2 = axes[0, 1]
        problematic_files = results.get('most_problematic_files', [])[:10]
        if problematic_files:
            file_names = [os.path.basename(f[0])[:20] + '...' if len(os.path.basename(f[0])) > 20 
                         else os.path.basename(f[0]) for f in problematic_files]
            clone_counts = [f[1] for f in problematic_files]
            
            bars = ax2.barh(range(len(file_names)), clone_counts, color='#FF6B6B', alpha=0.7)
            ax2.set_yticks(range(len(file_names)))
            ax2.set_yticklabels(file_names, color='white', fontsize=8)
            ax2.set_xlabel('Clone Count', color='white')
            ax2.set_title('Files with Most Clones', color='white', fontweight='bold')
            ax2.tick_params(colors='white')
            
            # Add value labels on bars
            for i, (bar, count) in enumerate(zip(bars, clone_counts)):
                ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                        str(count), ha='left', va='center', color='white', fontsize=8)
        else:
            ax2.text(0.5, 0.5, 'No problematic files', ha='center', va='center', 
                    transform=ax2.transAxes, color='white')
        
        ax2.set_facecolor('#2a2a2a')
        
        # Similarity distribution (histogram)
        ax3 = axes[1, 0]
        clone_groups = results.get('clone_groups', [])
        if clone_groups:
            similarities = [group['similarity'] for group in clone_groups]
            
            ax3.hist(similarities, bins=10, color='#4ECDC4', alpha=0.7, edgecolor='white')
            ax3.set_xlabel('Similarity Score', color='white')
            ax3.set_ylabel('Number of Clone Groups', color='white')
            ax3.set_title('Clone Similarity Distribution', color='white', fontweight='bold')
            ax3.tick_params(colors='white')
        else:
            ax3.text(0.5, 0.5, 'No similarity data', ha='center', va='center', 
                    transform=ax3.transAxes, color='white')
        
        ax3.set_facecolor('#2a2a2a')
        
        # Refactoring effort vs impact (scatter plot)
        ax4 = axes[1, 1]
        if clone_groups:
            efforts = []
            impacts = []
            priorities = []
            
            for group in clone_groups:
                refactoring = group.get('refactoring_opportunity', {})
                if refactoring:
                    efforts.append(refactoring.get('estimated_time_hours', 0))
                    
                    # Convert impact to numeric
                    impact_map = {'Low': 1, 'Medium': 2, 'High': 3}
                    impacts.append(impact_map.get(refactoring.get('impact', 'Low'), 1))
                    
                    # Color by priority
                    priority_colors = {'Low': '#96CEB4', 'Medium': '#FFEAA7', 'High': '#FF6B6B'}
                    priorities.append(priority_colors.get(refactoring.get('priority', 'Low'), '#96CEB4'))
            
            if efforts and impacts:
                scatter = ax4.scatter(efforts, impacts, c=priorities, alpha=0.7, s=60)
                ax4.set_xlabel('Estimated Effort (hours)', color='white')
                ax4.set_ylabel('Impact Level', color='white')
                ax4.set_title('Refactoring Effort vs Impact', color='white', fontweight='bold')
                ax4.set_yticks([1, 2, 3])
                ax4.set_yticklabels(['Low', 'Medium', 'High'])
                ax4.tick_params(colors='white')
            else:
                ax4.text(0.5, 0.5, 'No refactoring data', ha='center', va='center', 
                        transform=ax4.transAxes, color='white')
        else:
            ax4.text(0.5, 0.5, 'No refactoring data', ha='center', va='center', 
                    transform=ax4.transAxes, color='white')
        
        ax4.set_facecolor('#2a2a2a')
        
        plt.tight_layout()
    
    def _create_file_visualization(self, axes):
        """Create visualization for single file analysis results"""
        results = self.current_results
        clone_groups = results.get('clone_groups', [])
        
        # Clone locations in file (line chart)
        ax1 = axes[0, 0]
        if clone_groups:
            for i, group in enumerate(clone_groups):
                for block in group['blocks']:
                    start_line = block['start_line']
                    end_line = block['end_line']
                    ax1.barh(i, end_line - start_line, left=start_line, 
                            alpha=0.7, label=f"Group {i+1}")
            
            ax1.set_xlabel('Line Number', color='white')
            ax1.set_ylabel('Clone Group', color='white')
            ax1.set_title('Clone Locations in File', color='white', fontweight='bold')
            ax1.tick_params(colors='white')
        else:
            ax1.text(0.5, 0.5, 'No clones detected', ha='center', va='center', 
                    transform=ax1.transAxes, color='white')
        
        ax1.set_facecolor('#2a2a2a')
        
        # Clone sizes (bar chart)
        ax2 = axes[0, 1]
        if clone_groups:
            group_names = [f"Group {i+1}" for i in range(len(clone_groups))]
            clone_sizes = [group['clone_size'] for group in clone_groups]
            
            bars = ax2.bar(group_names, clone_sizes, color='#4ECDC4', alpha=0.7)
            ax2.set_xlabel('Clone Group', color='white')
            ax2.set_ylabel('Clone Size (lines)', color='white')
            ax2.set_title('Clone Sizes', color='white', fontweight='bold')
            ax2.tick_params(colors='white')
            
            # Add value labels on bars
            for bar, size in zip(bars, clone_sizes):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                        str(size), ha='center', va='bottom', color='white')
        else:
            ax2.text(0.5, 0.5, 'No clone sizes', ha='center', va='center', 
                    transform=ax2.transAxes, color='white')
        
        ax2.set_facecolor('#2a2a2a')
        
        # Similarity scores (bar chart)
        ax3 = axes[1, 0]
        if clone_groups:
            similarities = [group['similarity'] for group in clone_groups]
            
            bars = ax3.bar(group_names, similarities, color='#FF6B6B', alpha=0.7)
            ax3.set_xlabel('Clone Group', color='white')
            ax3.set_ylabel('Similarity Score', color='white')
            ax3.set_title('Clone Similarity Scores', color='white', fontweight='bold')
            ax3.set_ylim(0, 1)
            ax3.tick_params(colors='white')
            
            # Add value labels on bars
            for bar, sim in zip(bars, similarities):
                ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                        f'{sim:.2f}', ha='center', va='bottom', color='white')
        else:
            ax3.text(0.5, 0.5, 'No similarity data', ha='center', va='center', 
                    transform=ax3.transAxes, color='white')
        
        ax3.set_facecolor('#2a2a2a')
        
        # File statistics (text display)
        ax4 = axes[1, 1]
        ax4.axis('off')
        
        stats_text = f"""File Statistics:
        
Total Lines: {results['total_lines']}
Code Blocks: {results['code_blocks']}
Clone Groups: {len(clone_groups)}

Clone Types:
"""
        
        if clone_groups:
            type_counts = {}
            for group in clone_groups:
                clone_type = group['type']
                type_counts[clone_type] = type_counts.get(clone_type, 0) + 1
            
            for clone_type, count in type_counts.items():
                stats_text += f"• {clone_type.replace('_', ' ').title()}: {count}\n"
        else:
            stats_text += "• No clones detected"
        
        ax4.text(0.1, 0.9, stats_text, transform=ax4.transAxes, color='white',
                fontsize=10, verticalalignment='top', fontfamily='monospace')
        ax4.set_facecolor('#2a2a2a')
        
        plt.tight_layout()
    
    def _create_refactoring_suggestions(self):
        """Create detailed refactoring suggestions"""
        if not self.current_results:
            return {}
        
        if 'refactoring_opportunities' in self.current_results:
            # Directory analysis
            opportunities = self.current_results['refactoring_opportunities']
            return {
                'summary': {
                    'total_groups': len(self.current_results.get('clone_groups', [])),
                    'high_priority': len(opportunities.get('high_priority', [])),
                    'total_hours': opportunities.get('total_estimated_hours', 0)
                },
                'high_priority': opportunities.get('high_priority', []),
                'medium_priority': opportunities.get('medium_priority', []),
                'low_priority': opportunities.get('low_priority', [])
            }
        else:
            # Single file analysis
            clone_groups = self.current_results.get('clone_groups', [])
            high_priority = []
            medium_priority = []
            low_priority = []
            total_hours = 0
            
            for group in clone_groups:
                refactoring = group.get('refactoring_opportunity', {})
                if not refactoring:
                    continue
                
                priority = refactoring.get('priority', 'Low')
                estimated_hours = refactoring.get('estimated_time_hours', 0)
                total_hours += estimated_hours
                
                opportunity = {
                    'description': refactoring.get('description', ''),
                    'strategy': refactoring.get('strategy', ''),
                    'clone_count': len(group['blocks']),
                    'similarity': group['similarity'],
                    'estimated_hours': estimated_hours,
                    'files_affected': [self.current_results['file_path']]
                }
                
                if priority == 'High':
                    high_priority.append(opportunity)
                elif priority == 'Medium':
                    medium_priority.append(opportunity)
                else:
                    low_priority.append(opportunity)
            
            return {
                'summary': {
                    'total_groups': len(clone_groups),
                    'high_priority': len(high_priority),
                    'total_hours': total_hours
                },
                'high_priority': high_priority,
                'medium_priority': medium_priority,
                'low_priority': low_priority
            }
    
    def generate_recommendations(self):
        """Generate general recommendations based on clone analysis"""
        if not self.current_results:
            return []
        
        recommendations = []
        
        if 'summary' in self.current_results:
            # Directory analysis recommendations
            summary = self.current_results['summary']
            duplication_pct = summary.get('duplication_percentage', 0)
            
            if duplication_pct > 20:
                recommendations.append("High code duplication detected - immediate refactoring recommended")
            elif duplication_pct > 10:
                recommendations.append("Moderate code duplication - consider refactoring in next sprint")
            elif duplication_pct > 5:
                recommendations.append("Low code duplication - monitor and refactor opportunistically")
            else:
                recommendations.append("Good code quality - minimal duplication detected")
            
            exact_clones = summary.get('exact_clones', 0)
            if exact_clones > 0:
                recommendations.append(f"Focus on {exact_clones} exact clones first for quick wins")
            
            if summary.get('total_clones_found', 0) > 50:
                recommendations.append("Consider implementing coding standards to prevent future duplication")
        
        else:
            # Single file recommendations
            clone_count = self.current_results.get('internal_clones', 0)
            
            if clone_count > 5:
                recommendations.append("High internal duplication - consider breaking file into smaller modules")
            elif clone_count > 2:
                recommendations.append("Some internal duplication - extract common functionality")
            elif clone_count > 0:
                recommendations.append("Minor duplication detected - consider refactoring when convenient")
            else:
                recommendations.append("No internal duplication detected - good code structure")
        
        return recommendations
    
    def _extract_key_metrics(self):
        """Extract key metrics for database storage"""
        if not self.current_results:
            return {}
        
        if 'summary' in self.current_results:
            summary = self.current_results['summary']
            return {
                'total_files': summary.get('total_files_analyzed', 0),
                'total_lines': summary.get('total_lines_analyzed', 0),
                'total_clones': summary.get('total_clones_found', 0),
                'duplication_percentage': summary.get('duplication_percentage', 0),
                'exact_clones': summary.get('exact_clones', 0),
                'near_clones': summary.get('near_clones', 0)
            }
        else:
            return {
                'total_files': 1,
                'total_lines': self.current_results.get('total_lines', 0),
                'total_clones': self.current_results.get('internal_clones', 0),
                'code_blocks': self.current_results.get('code_blocks', 0)
            }