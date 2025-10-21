import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from base_tool import AdvancedToolFrame
from theme import style_button, style_label, style_entry, style_textbox, BG_COLOR, PANEL_COLOR, TEXT_COLOR
import ast
import os
import re
import json
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

TAB_NAME = "Refactoring Opportunity Identifier"

class RefactoringAnalyzer:
    """Core refactoring opportunity analysis engine"""
    
    def __init__(self):
        self.reset_metrics()
        
        # Refactoring patterns and their characteristics
        self.refactoring_patterns = {
            'extract_method': {
                'description': 'Extract Method - Break down large methods into smaller ones',
                'effort_multiplier': 1.0,
                'impact_score': 3,
                'complexity_threshold': 10
            },
            'extract_class': {
                'description': 'Extract Class - Split large classes into focused classes',
                'effort_multiplier': 2.5,
                'impact_score': 4,
                'method_threshold': 15
            },
            'eliminate_duplication': {
                'description': 'Eliminate Duplication - Remove duplicate code blocks',
                'effort_multiplier': 1.5,
                'impact_score': 3,
                'similarity_threshold': 0.8
            },
            'simplify_conditionals': {
                'description': 'Simplify Conditionals - Reduce complex conditional logic',
                'effort_multiplier': 1.2,
                'impact_score': 2,
                'nesting_threshold': 3
            },
            'introduce_parameter_object': {
                'description': 'Introduce Parameter Object - Group related parameters',
                'effort_multiplier': 1.8,
                'impact_score': 2,
                'parameter_threshold': 5
            },
            'replace_magic_numbers': {
                'description': 'Replace Magic Numbers - Use named constants',
                'effort_multiplier': 0.5,
                'impact_score': 1,
                'magic_number_threshold': 3
            },
            'improve_naming': {
                'description': 'Improve Naming - Use more descriptive names',
                'effort_multiplier': 0.8,
                'impact_score': 2,
                'naming_score_threshold': 0.3
            },
            'reduce_dependencies': {
                'description': 'Reduce Dependencies - Minimize coupling between modules',
                'effort_multiplier': 3.0,
                'impact_score': 4,
                'dependency_threshold': 10
            }
        }
        
        # Effort estimation factors (hours per occurrence)
        self.base_effort_hours = {
            'trivial': 0.5,
            'minor': 2.0,
            'moderate': 6.0,
            'major': 16.0,
            'critical': 40.0
        }
    
    def reset_metrics(self):
        """Reset all metrics for new analysis"""
        self.refactoring_opportunities = []
        self.file_metrics = {}
        self.code_smells = []
        self.complexity_metrics = {}
        
    def analyze_file(self, file_path):
        """Analyze a single file for refactoring opportunities"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.py':
                return self._analyze_python_file(file_path, content)
            else:
                return self._analyze_generic_file(file_path, content)
                
        except Exception as e:
            raise Exception(f"Error analyzing file {file_path}: {e}")
    
    def analyze_directory(self, directory_path):
        """Analyze all files in a directory for refactoring opportunities"""
        results = []
        code_extensions = ['.py', '.js', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs']
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', '.vscode', '.idea']]
            
            for file in files:
                if any(file.lower().endswith(ext) for ext in code_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        file_result = self.analyze_file(file_path)
                        results.append(file_result)
                    except Exception as e:
                        print(f"Error analyzing {file_path}: {e}")
                        continue
        
        return self._aggregate_results(results)
    
    def _analyze_python_file(self, file_path, content):
        """Analyze Python file using AST parsing"""
        try:
            tree = ast.parse(content, filename=file_path)
            lines = content.split('\n')
            
            opportunities = []
            
            # Analyze AST nodes for refactoring opportunities
            for node in ast.walk(tree):
                opportunities.extend(self._check_python_refactoring_patterns(node, lines))
            
            # Check for code smells and general refactoring opportunities
            opportunities.extend(self._check_general_refactoring_patterns(content, lines))
            
            # Check for duplication patterns
            opportunities.extend(self._check_duplication_patterns(content, lines))
            
            return self._calculate_refactoring_score(file_path, opportunities, len(lines))
            
        except SyntaxError as e:
            return {
                'file_path': file_path,
                'error': f"Syntax error: {e}",
                'refactoring_score': 0,
                'opportunities': []
            }
    
    def _analyze_generic_file(self, file_path, content):
        """Generic analysis for non-Python files"""
        lines = content.split('\n')
        opportunities = []
        
        # Check for general refactoring patterns
        opportunities.extend(self._check_general_refactoring_patterns(content, lines))
        
        # Check for duplication patterns
        opportunities.extend(self._check_duplication_patterns(content, lines))
        
        # Check for basic complexity indicators
        opportunities.extend(self._check_generic_complexity_patterns(content, lines))
        
        return self._calculate_refactoring_score(file_path, opportunities, len(lines))
    
    def _check_python_refactoring_patterns(self, node, lines):
        """Check Python AST node for refactoring opportunities"""
        opportunities = []
        
        # Extract Method opportunities
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_complexity = self._calculate_function_complexity(node)
            func_length = self._calculate_function_length(node)
            
            if func_complexity > self.refactoring_patterns['extract_method']['complexity_threshold']:
                effort = self._estimate_effort('extract_method', func_complexity)
                impact = self._calculate_impact('extract_method', func_complexity)
                
                opportunities.append({
                    'pattern': 'extract_method',
                    'severity': self._determine_severity(func_complexity, 10, 20, 30),
                    'line': node.lineno,
                    'element': f"Function '{node.name}'",
                    'description': f"Function has high complexity ({func_complexity}) - consider extracting methods",
                    'effort_hours': effort,
                    'impact_score': impact,
                    'guidance': self._generate_extract_method_guidance(node, func_complexity),
                    'metrics': {'complexity': func_complexity, 'length': func_length}
                })
            
            # Long method detection
            if func_length > 50:
                effort = self._estimate_effort('extract_method', func_length / 10)
                impact = self._calculate_impact('extract_method', func_length / 10)
                
                opportunities.append({
                    'pattern': 'extract_method',
                    'severity': self._determine_severity(func_length, 50, 100, 150),
                    'line': node.lineno,
                    'element': f"Function '{node.name}'",
                    'description': f"Function is too long ({func_length} lines) - consider breaking it down",
                    'effort_hours': effort,
                    'impact_score': impact,
                    'guidance': self._generate_long_method_guidance(node, func_length),
                    'metrics': {'length': func_length}
                })
            
            # Parameter list too long
            param_count = len(node.args.args)
            if param_count > self.refactoring_patterns['introduce_parameter_object']['parameter_threshold']:
                effort = self._estimate_effort('introduce_parameter_object', param_count)
                impact = self._calculate_impact('introduce_parameter_object', param_count)
                
                opportunities.append({
                    'pattern': 'introduce_parameter_object',
                    'severity': self._determine_severity(param_count, 5, 8, 12),
                    'line': node.lineno,
                    'element': f"Function '{node.name}'",
                    'description': f"Function has too many parameters ({param_count}) - consider parameter object",
                    'effort_hours': effort,
                    'impact_score': impact,
                    'guidance': self._generate_parameter_object_guidance(node, param_count),
                    'metrics': {'parameter_count': param_count}
                })
        
        # Extract Class opportunities
        elif isinstance(node, ast.ClassDef):
            methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            method_count = len(methods)
            
            if method_count > self.refactoring_patterns['extract_class']['method_threshold']:
                effort = self._estimate_effort('extract_class', method_count)
                impact = self._calculate_impact('extract_class', method_count)
                
                opportunities.append({
                    'pattern': 'extract_class',
                    'severity': self._determine_severity(method_count, 15, 25, 35),
                    'line': node.lineno,
                    'element': f"Class '{node.name}'",
                    'description': f"Class has too many methods ({method_count}) - consider splitting",
                    'effort_hours': effort,
                    'impact_score': impact,
                    'guidance': self._generate_extract_class_guidance(node, method_count),
                    'metrics': {'method_count': method_count}
                })
        
        # Complex conditional patterns
        elif isinstance(node, ast.If):
            nesting_level = self._calculate_nesting_level(node)
            if nesting_level > self.refactoring_patterns['simplify_conditionals']['nesting_threshold']:
                effort = self._estimate_effort('simplify_conditionals', nesting_level)
                impact = self._calculate_impact('simplify_conditionals', nesting_level)
                
                opportunities.append({
                    'pattern': 'simplify_conditionals',
                    'severity': self._determine_severity(nesting_level, 3, 5, 7),
                    'line': node.lineno,
                    'element': "Conditional statement",
                    'description': f"Complex nested conditionals (depth {nesting_level}) - consider simplification",
                    'effort_hours': effort,
                    'impact_score': impact,
                    'guidance': self._generate_conditional_guidance(node, nesting_level),
                    'metrics': {'nesting_level': nesting_level}
                })
        
        return opportunities
    
    def _check_general_refactoring_patterns(self, content, lines):
        """Check for general refactoring patterns applicable to any language"""
        opportunities = []
        
        # Magic numbers detection
        magic_numbers = []
        for line_num, line in enumerate(lines, 1):
            # Look for numeric literals (excluding common values like 0, 1, 2)
            magic_pattern = r'\b(?<![\w.])((?:[3-9]|[1-9]\d+)(?:\.\d+)?)\b(?![\w.])'
            matches = re.findall(magic_pattern, line)
            if matches and not line.strip().startswith('#'):
                magic_numbers.extend([(line_num, match) for match in matches])
        
        if len(magic_numbers) > self.refactoring_patterns['replace_magic_numbers']['magic_number_threshold']:
            effort = self._estimate_effort('replace_magic_numbers', len(magic_numbers))
            impact = self._calculate_impact('replace_magic_numbers', len(magic_numbers))
            
            opportunities.append({
                'pattern': 'replace_magic_numbers',
                'severity': self._determine_severity(len(magic_numbers), 3, 8, 15),
                'line': magic_numbers[0][0] if magic_numbers else 1,
                'element': "Magic numbers",
                'description': f"Found {len(magic_numbers)} magic numbers - consider using named constants",
                'effort_hours': effort,
                'impact_score': impact,
                'guidance': self._generate_magic_number_guidance(magic_numbers),
                'metrics': {'magic_number_count': len(magic_numbers)}
            })
        
        # Poor naming detection
        poor_names = []
        for line_num, line in enumerate(lines, 1):
            # Look for short variable names or non-descriptive names
            poor_name_patterns = [
                r'\b[a-z]{1,2}\b\s*=',  # Single/double letter variables
                r'\bdata\d*\b',         # Generic 'data' variables
                r'\btemp\d*\b',         # Temporary variables
                r'\bvar\d*\b',          # Generic 'var' variables
                r'\bitem\d*\b'          # Generic 'item' variables
            ]
            
            for pattern in poor_name_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    poor_names.append(line_num)
                    break
        
        if len(poor_names) > 5:  # Threshold for poor naming
            effort = self._estimate_effort('improve_naming', len(poor_names))
            impact = self._calculate_impact('improve_naming', len(poor_names))
            
            opportunities.append({
                'pattern': 'improve_naming',
                'severity': self._determine_severity(len(poor_names), 5, 15, 30),
                'line': poor_names[0] if poor_names else 1,
                'element': "Variable names",
                'description': f"Found {len(poor_names)} poorly named variables - consider more descriptive names",
                'effort_hours': effort,
                'impact_score': impact,
                'guidance': self._generate_naming_guidance(poor_names),
                'metrics': {'poor_name_count': len(poor_names)}
            })
        
        return opportunities
    
    def _check_duplication_patterns(self, content, lines):
        """Check for code duplication patterns"""
        opportunities = []
        
        # Simple line-based duplication detection
        line_groups = {}
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if len(stripped) > 10 and not stripped.startswith('#'):  # Ignore short lines and comments
                if stripped in line_groups:
                    line_groups[stripped].append(line_num)
                else:
                    line_groups[stripped] = [line_num]
        
        # Find duplicated lines
        duplicated_lines = {line: nums for line, nums in line_groups.items() if len(nums) > 1}
        
        if duplicated_lines:
            total_duplicates = sum(len(nums) - 1 for nums in duplicated_lines.values())
            effort = self._estimate_effort('eliminate_duplication', total_duplicates)
            impact = self._calculate_impact('eliminate_duplication', total_duplicates)
            
            opportunities.append({
                'pattern': 'eliminate_duplication',
                'severity': self._determine_severity(total_duplicates, 3, 10, 20),
                'line': min(min(nums) for nums in duplicated_lines.values()),
                'element': "Duplicated code",
                'description': f"Found {total_duplicates} duplicated lines across {len(duplicated_lines)} patterns",
                'effort_hours': effort,
                'impact_score': impact,
                'guidance': self._generate_duplication_guidance(duplicated_lines),
                'metrics': {'duplicate_count': total_duplicates, 'pattern_count': len(duplicated_lines)}
            })
        
        return opportunities
    
    def _check_generic_complexity_patterns(self, content, lines):
        """Check for complexity patterns in any language"""
        opportunities = []
        
        # Deep nesting detection
        max_nesting = 0
        current_nesting = 0
        nesting_lines = []
        
        for line_num, line in enumerate(lines, 1):
            # Count opening and closing braces/brackets
            opens = line.count('{') + line.count('(') + line.count('[')
            closes = line.count('}') + line.count(')') + line.count(']')
            
            # Also check indentation-based nesting (Python-style)
            indent_level = (len(line) - len(line.lstrip())) // 4  # Assuming 4-space indentation
            
            current_nesting += opens - closes
            current_nesting = max(0, current_nesting)  # Don't go negative
            
            # Use the higher of brace-based or indent-based nesting
            effective_nesting = max(current_nesting, indent_level)
            
            if effective_nesting > max_nesting:
                max_nesting = effective_nesting
                nesting_lines.append(line_num)
        
        if max_nesting > 4:  # Deep nesting threshold
            effort = self._estimate_effort('simplify_conditionals', max_nesting)
            impact = self._calculate_impact('simplify_conditionals', max_nesting)
            
            opportunities.append({
                'pattern': 'simplify_conditionals',
                'severity': self._determine_severity(max_nesting, 4, 6, 8),
                'line': nesting_lines[0] if nesting_lines else 1,
                'element': "Nested code blocks",
                'description': f"Deep nesting detected (max depth {max_nesting}) - consider flattening structure",
                'effort_hours': effort,
                'impact_score': impact,
                'guidance': self._generate_nesting_guidance(max_nesting),
                'metrics': {'max_nesting': max_nesting}
            })
        
        return opportunities    

    def _calculate_function_complexity(self, node):
        """Calculate cyclomatic complexity of a function"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
        
        return complexity
    
    def _calculate_function_length(self, node):
        """Calculate function length in lines"""
        if hasattr(node, 'end_lineno') and node.end_lineno:
            return node.end_lineno - node.lineno
        return 0
    
    def _calculate_nesting_level(self, node):
        """Calculate maximum nesting level in a node"""
        max_depth = 0
        
        def count_depth(n, current_depth=0):
            nonlocal max_depth
            max_depth = max(max_depth, current_depth)
            
            if isinstance(n, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.With, ast.AsyncWith, ast.Try)):
                for child in ast.iter_child_nodes(n):
                    count_depth(child, current_depth + 1)
            else:
                for child in ast.iter_child_nodes(n):
                    count_depth(child, current_depth)
        
        count_depth(node)
        return max_depth
    
    def _estimate_effort(self, pattern, metric_value):
        """Estimate effort required for refactoring"""
        pattern_info = self.refactoring_patterns.get(pattern, {})
        base_effort = self.base_effort_hours.get('moderate', 6.0)
        multiplier = pattern_info.get('effort_multiplier', 1.0)
        
        # Scale effort based on metric value
        if metric_value <= 5:
            effort_category = 'trivial'
        elif metric_value <= 10:
            effort_category = 'minor'
        elif metric_value <= 20:
            effort_category = 'moderate'
        elif metric_value <= 40:
            effort_category = 'major'
        else:
            effort_category = 'critical'
        
        base_effort = self.base_effort_hours.get(effort_category, 6.0)
        return round(base_effort * multiplier, 1)
    
    def _calculate_impact(self, pattern, metric_value):
        """Calculate impact score for refactoring"""
        pattern_info = self.refactoring_patterns.get(pattern, {})
        base_impact = pattern_info.get('impact_score', 2)
        
        # Scale impact based on metric value
        if metric_value > 30:
            return base_impact * 2
        elif metric_value > 15:
            return base_impact * 1.5
        else:
            return base_impact
    
    def _determine_severity(self, value, low_threshold, medium_threshold, high_threshold):
        """Determine severity level based on thresholds"""
        if value >= high_threshold:
            return 'critical'
        elif value >= medium_threshold:
            return 'major'
        elif value >= low_threshold:
            return 'moderate'
        else:
            return 'minor'
    
    def _generate_extract_method_guidance(self, node, complexity):
        """Generate step-by-step guidance for extract method refactoring"""
        steps = [
            "1. Identify logical blocks within the function that can be extracted",
            "2. Look for code segments that perform a single, well-defined task",
            "3. Extract these segments into separate methods with descriptive names",
            "4. Pass necessary parameters and return appropriate values",
            "5. Update the original function to call the new methods",
            "6. Test thoroughly to ensure behavior is preserved"
        ]
        
        if complexity > 20:
            steps.insert(1, "1.5. Consider breaking this into multiple smaller refactoring steps")
        
        return {
            'steps': steps,
            'estimated_methods': max(2, complexity // 5),
            'priority': 'high' if complexity > 20 else 'medium',
            'tools_suggested': ['IDE refactoring tools', 'Extract method automation'],
            'testing_notes': 'Ensure all edge cases are covered in tests before refactoring'
        }
    
    def _generate_long_method_guidance(self, node, length):
        """Generate guidance for long method refactoring"""
        steps = [
            "1. Read through the method and identify distinct responsibilities",
            "2. Group related lines of code together",
            "3. Extract each group into a separate method with a clear name",
            "4. Consider the Single Responsibility Principle",
            "5. Refactor incrementally, testing after each extraction",
            "6. Review the final structure for clarity and maintainability"
        ]
        
        return {
            'steps': steps,
            'estimated_methods': max(2, length // 25),
            'priority': 'high' if length > 100 else 'medium',
            'tools_suggested': ['Code folding', 'Method extraction tools'],
            'testing_notes': 'Create comprehensive tests before starting refactoring'
        }
    
    def _generate_parameter_object_guidance(self, node, param_count):
        """Generate guidance for parameter object refactoring"""
        steps = [
            "1. Identify parameters that are logically related",
            "2. Create a new class or data structure to hold these parameters",
            "3. Replace the parameter list with the new parameter object",
            "4. Update all callers to use the new parameter object",
            "5. Consider adding validation to the parameter object",
            "6. Update documentation and tests"
        ]
        
        return {
            'steps': steps,
            'estimated_objects': max(1, param_count // 4),
            'priority': 'medium',
            'tools_suggested': ['Refactoring IDE features', 'Data class generators'],
            'testing_notes': 'Verify all parameter combinations still work correctly'
        }
    
    def _generate_extract_class_guidance(self, node, method_count):
        """Generate guidance for extract class refactoring"""
        steps = [
            "1. Analyze the class to identify cohesive groups of methods and data",
            "2. Look for methods that work with the same subset of instance variables",
            "3. Create new classes for each cohesive group",
            "4. Move related methods and data to the new classes",
            "5. Update the original class to use composition or delegation",
            "6. Ensure proper encapsulation and interface design"
        ]
        
        return {
            'steps': steps,
            'estimated_classes': max(2, method_count // 10),
            'priority': 'high' if method_count > 30 else 'medium',
            'tools_suggested': ['Class extraction tools', 'Dependency analysis'],
            'testing_notes': 'Maintain existing public interface during refactoring'
        }
    
    def _generate_conditional_guidance(self, node, nesting_level):
        """Generate guidance for simplifying conditionals"""
        steps = [
            "1. Look for opportunities to use early returns or guard clauses",
            "2. Consider extracting complex conditions into well-named boolean methods",
            "3. Use polymorphism to replace type-checking conditionals",
            "4. Combine related conditional checks where possible",
            "5. Consider using strategy pattern for complex conditional logic",
            "6. Flatten nested if-else structures where appropriate"
        ]
        
        return {
            'steps': steps,
            'estimated_methods': max(1, nesting_level // 2),
            'priority': 'high' if nesting_level > 5 else 'medium',
            'tools_suggested': ['Conditional simplification tools', 'Boolean algebra'],
            'testing_notes': 'Test all conditional branches thoroughly'
        }
    
    def _generate_magic_number_guidance(self, magic_numbers):
        """Generate guidance for replacing magic numbers"""
        steps = [
            "1. Identify the meaning and purpose of each magic number",
            "2. Create well-named constants for each magic number",
            "3. Place constants in appropriate scope (class, module, or global)",
            "4. Replace all occurrences of the magic number with the constant",
            "5. Consider grouping related constants in enums or constant classes",
            "6. Update documentation to explain the constants"
        ]
        
        return {
            'steps': steps,
            'estimated_constants': len(set(num for _, num in magic_numbers)),
            'priority': 'low',
            'tools_suggested': ['Find and replace', 'Constant extraction tools'],
            'testing_notes': 'Verify that constant values match original magic numbers'
        }
    
    def _generate_naming_guidance(self, poor_names):
        """Generate guidance for improving naming"""
        steps = [
            "1. Review each poorly named variable/method/class",
            "2. Understand the purpose and responsibility of each element",
            "3. Choose descriptive names that clearly indicate purpose",
            "4. Follow consistent naming conventions for the language",
            "5. Avoid abbreviations and single-letter names (except for loops)",
            "6. Use domain-specific terminology where appropriate"
        ]
        
        return {
            'steps': steps,
            'estimated_renames': len(poor_names),
            'priority': 'low',
            'tools_suggested': ['Rename refactoring tools', 'Code review'],
            'testing_notes': 'Ensure renamed elements maintain same functionality'
        }
    
    def _generate_duplication_guidance(self, duplicated_lines):
        """Generate guidance for eliminating duplication"""
        steps = [
            "1. Identify the duplicated code blocks",
            "2. Analyze the context and variations in each duplication",
            "3. Extract common code into reusable methods or functions",
            "4. Parameterize the extracted code to handle variations",
            "5. Replace all duplicated instances with calls to the extracted code",
            "6. Consider creating utility classes for commonly duplicated patterns"
        ]
        
        return {
            'steps': steps,
            'estimated_extractions': len(duplicated_lines),
            'priority': 'medium',
            'tools_suggested': ['Duplicate code detection', 'Extract method tools'],
            'testing_notes': 'Verify that all variations of duplicated code still work'
        }
    
    def _generate_nesting_guidance(self, max_nesting):
        """Generate guidance for reducing nesting"""
        steps = [
            "1. Identify deeply nested code blocks",
            "2. Use early returns to reduce nesting levels",
            "3. Extract nested logic into separate methods",
            "4. Consider using guard clauses for validation",
            "5. Replace nested conditionals with polymorphism where appropriate",
            "6. Flatten loops by extracting inner logic to methods"
        ]
        
        return {
            'steps': steps,
            'estimated_methods': max(1, max_nesting // 2),
            'priority': 'medium',
            'tools_suggested': ['Nesting analysis tools', 'Code restructuring'],
            'testing_notes': 'Test all code paths after flattening structure'
        }
    
    def _calculate_refactoring_score(self, file_path, opportunities, total_lines):
        """Calculate overall refactoring score for a file"""
        total_score = 0
        pattern_counts = {}
        
        for opportunity in opportunities:
            pattern = opportunity['pattern']
            effort = opportunity['effort_hours']
            impact = opportunity['impact_score']
            
            # Calculate weighted score
            score = effort * impact
            total_score += score
            
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        # Normalize by file size
        normalized_score = total_score / max(total_lines / 100, 1)  # Per 100 lines
        
        return {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'refactoring_score': round(total_score, 2),
            'normalized_score': round(normalized_score, 2),
            'total_lines': total_lines,
            'opportunity_count': len(opportunities),
            'opportunities': opportunities,
            'pattern_counts': pattern_counts,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _aggregate_results(self, file_results):
        """Aggregate results from multiple files"""
        if not file_results:
            return {}
        
        total_score = sum(r.get('refactoring_score', 0) for r in file_results)
        total_opportunities = sum(r.get('opportunity_count', 0) for r in file_results)
        total_lines = sum(r.get('total_lines', 0) for r in file_results)
        
        # Aggregate pattern counts
        pattern_totals = {}
        for result in file_results:
            for pattern, count in result.get('pattern_counts', {}).items():
                pattern_totals[pattern] = pattern_totals.get(pattern, 0) + count
        
        # Sort files by refactoring score
        file_results.sort(key=lambda x: x.get('refactoring_score', 0), reverse=True)
        
        return {
            'summary': {
                'total_files': len(file_results),
                'total_refactoring_score': round(total_score, 2),
                'average_score_per_file': round(total_score / len(file_results), 2),
                'total_opportunities': total_opportunities,
                'total_lines': total_lines,
                'refactoring_density': round(total_score / max(total_lines / 1000, 1), 2),  # Per 1000 lines
                'pattern_totals': pattern_totals
            },
            'files': file_results,
            'analysis_timestamp': datetime.now().isoformat()
        }


class ToolFrame(AdvancedToolFrame):
    def __init__(self, master):
        super().__init__(master, {
            'name': 'Refactoring Opportunity Identifier',
            'tool_id': 'refactoring_opportunity_identifier',
            'category': 'Code Analysis'
        })
        
        self.analyzer = RefactoringAnalyzer()
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
        """Setup the control panel"""
        # Title
        title_label = tk.Label(parent, text="🔧 Refactoring Opportunity Identifier", 
                              bg=PANEL_COLOR, fg=TEXT_COLOR, font=("Consolas", 14, "bold"))
        title_label.pack(pady=10)
        
        # File/Directory selection
        selection_frame = tk.Frame(parent, bg=PANEL_COLOR)
        selection_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(selection_frame, text="Analysis Target:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.target_path_var = tk.StringVar()
        target_entry = tk.Entry(selection_frame, textvariable=self.target_path_var, 
                               bg="#111111", fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        target_entry.pack(fill="x", pady=2)
        
        button_frame = tk.Frame(selection_frame, bg=PANEL_COLOR)
        button_frame.pack(fill="x", pady=2)
        
        file_btn = tk.Button(button_frame, text="Select File", command=self.browse_file)
        style_button(file_btn)
        file_btn.pack(side="left", padx=2, fill="x", expand=True)
        
        dir_btn = tk.Button(button_frame, text="Select Directory", command=self.browse_directory)
        style_button(dir_btn)
        dir_btn.pack(side="right", padx=2, fill="x", expand=True)
        
        # Analysis options
        options_frame = tk.Frame(parent, bg=PANEL_COLOR)
        options_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(options_frame, text="Refactoring Patterns:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.pattern_vars = {}
        patterns = [
            ('extract_method', 'Extract Method'),
            ('extract_class', 'Extract Class'),
            ('eliminate_duplication', 'Eliminate Duplication'),
            ('simplify_conditionals', 'Simplify Conditionals'),
            ('improve_naming', 'Improve Naming'),
            ('replace_magic_numbers', 'Replace Magic Numbers')
        ]
        
        for pattern_key, pattern_name in patterns:
            var = tk.BooleanVar(value=True)
            self.pattern_vars[pattern_key] = var
            tk.Checkbutton(options_frame, text=pattern_name, variable=var,
                          bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor="#111111").pack(anchor="w")
        
        # Priority filter
        priority_frame = tk.Frame(parent, bg=PANEL_COLOR)
        priority_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(priority_frame, text="Minimum Priority:", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        self.priority_var = tk.StringVar(value="minor")
        priority_combo = ttk.Combobox(priority_frame, textvariable=self.priority_var,
                                     values=["minor", "moderate", "major", "critical"],
                                     state="readonly", width=15)
        priority_combo.pack(anchor="w", pady=2)
        
        # Effort thresholds
        threshold_frame = tk.Frame(parent, bg=PANEL_COLOR)
        threshold_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(threshold_frame, text="Effort Thresholds (hours):", bg=PANEL_COLOR, fg=TEXT_COLOR, 
                font=("Consolas", 10, "bold")).pack(anchor="w")
        
        # Max effort threshold
        effort_frame = tk.Frame(threshold_frame, bg=PANEL_COLOR)
        effort_frame.pack(fill="x", pady=1)
        tk.Label(effort_frame, text="Max Effort:", bg=PANEL_COLOR, fg=TEXT_COLOR, width=12).pack(side="left")
        self.max_effort_threshold = tk.Spinbox(effort_frame, from_=1, to=200, value=40, width=10,
                                              bg="#111111", fg=TEXT_COLOR)
        self.max_effort_threshold.pack(side="left")
        
        # Action buttons
        action_frame = tk.Frame(parent, bg=PANEL_COLOR)
        action_frame.pack(fill="x", padx=10, pady=20)
        
        analyze_btn = tk.Button(action_frame, text="🔍 Identify Opportunities", command=self.analyze_refactoring)
        style_button(analyze_btn)
        analyze_btn.pack(fill="x", pady=2)
        
        estimate_btn = tk.Button(action_frame, text="⏱ Estimate Effort", command=self.estimate_refactoring_effort)
        style_button(estimate_btn)
        estimate_btn.pack(fill="x", pady=2)
        
        guidance_btn = tk.Button(action_frame, text="📋 Generate Guidance", command=self.generate_refactoring_plan)
        style_button(guidance_btn)
        guidance_btn.pack(fill="x", pady=2)
        
        clear_btn = tk.Button(action_frame, text="🗑 Clear Results", command=self.clear_results)
        style_button(clear_btn)
        clear_btn.pack(fill="x", pady=2)
    
    def setup_visualization_panel(self, parent):
        """Setup the visualization panel"""
        # Visualization title
        viz_title = tk.Label(parent, text="📊 Refactoring Analysis Visualization", 
                            bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 12, "bold"))
        viz_title.pack(pady=10)
        
        # Matplotlib figure frame
        self.viz_frame = tk.Frame(parent, bg=BG_COLOR)
        self.viz_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Initial placeholder
        placeholder_label = tk.Label(self.viz_frame, text="Analyze code to see refactoring opportunities visualization",
                                    bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        placeholder_label.pack(expand=True)    

    def browse_file(self):
        """Browse and select a file for analysis"""
        file_path = filedialog.askopenfilename(
            title="Select Code File for Refactoring Analysis",
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
        directory = filedialog.askdirectory(title="Select Directory for Refactoring Analysis")
        
        if directory:
            self.target_path_var.set(directory)
    
    def analyze_refactoring(self):
        """Analyze refactoring opportunities for the selected target"""
        target_path = self.target_path_var.get().strip()
        
        if not target_path:
            messagebox.showerror("Error", "Please select a file or directory to analyze.")
            return
        
        if not os.path.exists(target_path):
            messagebox.showerror("Error", "Selected path does not exist.")
            return
        
        try:
            self.update_progress(10, "Starting refactoring analysis...")
            
            if os.path.isfile(target_path):
                # Single file analysis
                self.update_progress(30, "Analyzing file...")
                results = self.analyzer.analyze_file(target_path)
                self.current_results = {'files': [results], 'summary': self._create_single_file_summary(results)}
            else:
                # Directory analysis
                self.update_progress(30, "Scanning directory...")
                results = self.analyzer.analyze_directory(target_path)
                self.current_results = results
            
            self.update_progress(70, "Generating reports...")
            
            # Filter results based on selected patterns and priority
            self._filter_results()
            
            # Update results display
            self.update_results_display()
            
            # Generate visualization
            self.generate_refactoring_visualization()
            
            self.update_progress(100, "Analysis complete!")
            
            # Save results to database
            self.save_analysis_result(
                analysis_id=f"refactoring_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                input_data={'target_path': target_path},
                results_summary=self.current_results.get('summary', {}),
                detailed_findings=self.current_results.get('files', []),
                recommendations=self.generate_recommendations(),
                metrics=self._extract_key_metrics()
            )
            
            summary = self.current_results.get('summary', {})
            messagebox.showinfo("Analysis Complete", 
                              f"Refactoring Score: {summary.get('total_refactoring_score', 0)}\n"
                              f"Files Analyzed: {summary.get('total_files', 0)}\n"
                              f"Opportunities Found: {summary.get('total_opportunities', 0)}")
            
        except Exception as e:
            self.update_progress(0, f"Error: {str(e)}")
            messagebox.showerror("Analysis Error", f"Failed to analyze refactoring opportunities:\n{str(e)}")
    
    def estimate_refactoring_effort(self):
        """Estimate effort required for refactoring opportunities"""
        if not self.current_results:
            messagebox.showwarning("No Data", "Please run refactoring analysis first.")
            return
        
        try:
            effort_estimate = self._calculate_effort_estimate()
            
            # Display effort estimation
            effort_text = f"""Refactoring Effort Estimation Report
{'=' * 50}

Total Estimated Effort: {effort_estimate['total_hours']:.1f} hours ({effort_estimate['total_days']:.1f} days)

By Pattern:
"""
            for pattern, hours in effort_estimate['by_pattern'].items():
                if hours > 0:
                    pattern_name = pattern.replace('_', ' ').title()
                    effort_text += f"• {pattern_name}: {hours:.1f} hours\n"
            
            effort_text += f"""
By Priority:
• Critical: {effort_estimate['by_priority']['critical']:.1f} hours
• Major: {effort_estimate['by_priority']['major']:.1f} hours
• Moderate: {effort_estimate['by_priority']['moderate']:.1f} hours
• Minor: {effort_estimate['by_priority']['minor']:.1f} hours

Sprint Planning:
• Recommended sprint capacity: {effort_estimate['sprint_capacity']:.1f} hours
• Estimated sprints needed: {effort_estimate['estimated_sprints']}
• Completion timeline: {effort_estimate['estimated_weeks']} weeks

Recommendations:
• Start with critical and major opportunities for maximum impact
• Focus on extract_method and eliminate_duplication patterns first
• Consider dedicating 20-30% of sprint capacity to refactoring
"""
            
            self.update_results_tab("Analysis", effort_text)
            
            messagebox.showinfo("Effort Estimation", 
                              f"Total effort: {effort_estimate['total_hours']:.1f} hours\n"
                              f"Estimated sprints: {effort_estimate['estimated_sprints']}")
            
        except Exception as e:
            messagebox.showerror("Estimation Error", f"Failed to estimate effort:\n{str(e)}")
    
    def generate_refactoring_plan(self):
        """Generate detailed refactoring plan with step-by-step guidance"""
        if not self.current_results:
            messagebox.showwarning("No Data", "Please run refactoring analysis first.")
            return
        
        try:
            plan = self._create_refactoring_plan()
            
            plan_text = f"""Detailed Refactoring Plan
{'=' * 50}

Executive Summary:
• Total opportunities: {plan['summary']['total_opportunities']}
• Estimated effort: {plan['summary']['total_effort']:.1f} hours
• Priority distribution: {plan['summary']['priority_distribution']}

Phase 1: Critical Issues (Immediate Action Required)
{'-' * 50}
"""
            
            for i, item in enumerate(plan['phases']['critical'], 1):
                plan_text += f"{i}. {item['description']}\n"
                plan_text += f"   File: {item['file']}, Line: {item['line']}\n"
                plan_text += f"   Effort: {item['effort']} hours, Impact: {item['impact']}\n"
                plan_text += f"   Steps: {len(item['guidance']['steps'])} steps\n\n"
            
            plan_text += f"""
Phase 2: Major Issues (Next Sprint)
{'-' * 50}
"""
            
            for i, item in enumerate(plan['phases']['major'][:5], 1):  # Show top 5
                plan_text += f"{i}. {item['description']}\n"
                plan_text += f"   File: {item['file']}, Effort: {item['effort']} hours\n\n"
            
            plan_text += f"""
Phase 3: Moderate Issues (Future Sprints)
{'-' * 50}
"""
            
            for i, item in enumerate(plan['phases']['moderate'][:3], 1):  # Show top 3
                plan_text += f"{i}. {item['description']}\n"
                plan_text += f"   File: {item['file']}, Effort: {item['effort']} hours\n\n"
            
            plan_text += f"""
Implementation Guidelines:
• Review and prioritize based on current project needs
• Ensure comprehensive test coverage before refactoring
• Refactor incrementally to minimize risk
• Use automated refactoring tools where available
• Conduct code reviews for all refactoring changes
"""
            
            # Create a new tab for the refactoring plan
            if hasattr(self, 'results_notebook'):
                # Add plan tab if it doesn't exist
                tab_names = [self.results_notebook.tab(i, "text") for i in range(self.results_notebook.index("end"))]
                if "Refactoring Plan" not in tab_names:
                    plan_frame = tk.Frame(self.results_notebook, bg=BG_COLOR)
                    self.results_notebook.add(plan_frame, text="Refactoring Plan")
                    
                    plan_text_widget = tk.Text(plan_frame, bg="#111111", fg=TEXT_COLOR, 
                                             insertbackground=TEXT_COLOR, wrap="word")
                    plan_scrollbar = tk.Scrollbar(plan_frame, orient="vertical", command=plan_text_widget.yview)
                    plan_text_widget.configure(yscrollcommand=plan_scrollbar.set)
                    
                    plan_text_widget.pack(side="left", fill="both", expand=True)
                    plan_scrollbar.pack(side="right", fill="y")
                    
                    self.tab_frames["Refactoring Plan"] = plan_text_widget
                
                self.update_results_tab("Refactoring Plan", plan_text)
            
            messagebox.showinfo("Plan Generated", 
                              f"Refactoring plan created with {plan['summary']['total_opportunities']} opportunities")
            
        except Exception as e:
            messagebox.showerror("Plan Generation Error", f"Failed to generate refactoring plan:\n{str(e)}")
    
    def _filter_results(self):
        """Filter results based on selected patterns and priority"""
        if not self.current_results:
            return
        
        # Get selected patterns
        selected_patterns = [pattern for pattern, var in self.pattern_vars.items() if var.get()]
        min_priority = self.priority_var.get()
        max_effort = float(self.max_effort_threshold.get())
        
        # Priority order for filtering
        priority_order = {'minor': 0, 'moderate': 1, 'major': 2, 'critical': 3}
        min_priority_level = priority_order.get(min_priority, 0)
        
        # Filter opportunities in each file
        for file_result in self.current_results.get('files', []):
            filtered_opportunities = []
            
            for opportunity in file_result.get('opportunities', []):
                # Check pattern filter
                if opportunity['pattern'] not in selected_patterns:
                    continue
                
                # Check priority filter
                opp_priority_level = priority_order.get(opportunity['severity'], 0)
                if opp_priority_level < min_priority_level:
                    continue
                
                # Check effort filter
                if opportunity['effort_hours'] > max_effort:
                    continue
                
                filtered_opportunities.append(opportunity)
            
            file_result['opportunities'] = filtered_opportunities
            file_result['opportunity_count'] = len(filtered_opportunities)
            
            # Recalculate pattern counts
            pattern_counts = {}
            for opp in filtered_opportunities:
                pattern = opp['pattern']
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
            file_result['pattern_counts'] = pattern_counts
        
        # Recalculate summary
        if 'summary' in self.current_results:
            total_opportunities = sum(f.get('opportunity_count', 0) for f in self.current_results['files'])
            self.current_results['summary']['total_opportunities'] = total_opportunities
    
    def _create_single_file_summary(self, file_result):
        """Create summary for single file analysis"""
        return {
            'total_files': 1,
            'total_refactoring_score': file_result.get('refactoring_score', 0),
            'average_score_per_file': file_result.get('refactoring_score', 0),
            'total_opportunities': file_result.get('opportunity_count', 0),
            'total_lines': file_result.get('total_lines', 0),
            'refactoring_density': file_result.get('normalized_score', 0),
            'pattern_totals': file_result.get('pattern_counts', {})
        }
    
    def _calculate_effort_estimate(self):
        """Calculate effort estimation based on refactoring analysis"""
        if not self.current_results:
            return {}
        
        total_hours = 0
        by_pattern = {}
        by_priority = {'critical': 0, 'major': 0, 'moderate': 0, 'minor': 0}
        
        files = self.current_results.get('files', [])
        
        for file_result in files:
            for opportunity in file_result.get('opportunities', []):
                severity = opportunity.get('severity', 'minor')
                pattern = opportunity.get('pattern', 'extract_method')
                effort_hours = opportunity.get('effort_hours', 2.0)
                
                total_hours += effort_hours
                by_pattern[pattern] = by_pattern.get(pattern, 0) + effort_hours
                by_priority[severity] += effort_hours
        
        # Calculate sprint estimates (assuming 30% of 40-hour sprint for refactoring)
        sprint_capacity = 12  # 30% of 40 hours
        estimated_sprints = max(1, int(total_hours / sprint_capacity) + (1 if total_hours % sprint_capacity > 0 else 0))
        estimated_weeks = estimated_sprints * 2  # 2-week sprints
        
        return {
            'total_hours': total_hours,
            'total_days': total_hours / 8,  # 8 hours per day
            'by_pattern': by_pattern,
            'by_priority': by_priority,
            'sprint_capacity': sprint_capacity,
            'estimated_sprints': estimated_sprints,
            'estimated_weeks': estimated_weeks
        }
    
    def _create_refactoring_plan(self):
        """Create detailed refactoring plan with phases"""
        if not self.current_results:
            return {}
        
        # Collect all opportunities
        all_opportunities = []
        for file_result in self.current_results.get('files', []):
            for opportunity in file_result.get('opportunities', []):
                all_opportunities.append({
                    'file': file_result['file_name'],
                    'line': opportunity['line'],
                    'pattern': opportunity['pattern'],
                    'severity': opportunity['severity'],
                    'description': opportunity['description'],
                    'effort': opportunity['effort_hours'],
                    'impact': opportunity['impact_score'],
                    'guidance': opportunity['guidance']
                })
        
        # Sort by priority and impact
        priority_order = {'critical': 3, 'major': 2, 'moderate': 1, 'minor': 0}
        all_opportunities.sort(key=lambda x: (priority_order[x['severity']], x['impact'], x['effort']), reverse=True)
        
        # Group by phases
        phases = {
            'critical': [opp for opp in all_opportunities if opp['severity'] == 'critical'],
            'major': [opp for opp in all_opportunities if opp['severity'] == 'major'],
            'moderate': [opp for opp in all_opportunities if opp['severity'] == 'moderate'],
            'minor': [opp for opp in all_opportunities if opp['severity'] == 'minor']
        }
        
        # Calculate summary
        total_effort = sum(opp['effort'] for opp in all_opportunities)
        priority_distribution = {severity: len(opps) for severity, opps in phases.items() if opps}
        
        return {
            'summary': {
                'total_opportunities': len(all_opportunities),
                'total_effort': total_effort,
                'priority_distribution': priority_distribution
            },
            'phases': phases
        }
    
    def update_results_display(self):
        """Update the results tabs with refactoring analysis data"""
        if not self.current_results:
            return
        
        summary = self.current_results.get('summary', {})
        files = self.current_results.get('files', [])
        
        # Summary tab
        summary_text = f"""Refactoring Opportunity Analysis Summary
{'=' * 50}

Overall Metrics:
• Total Files Analyzed: {summary.get('total_files', 0)}
• Total Refactoring Score: {summary.get('total_refactoring_score', 0):.2f}
• Average Score per File: {summary.get('average_score_per_file', 0):.2f}
• Total Opportunities Found: {summary.get('total_opportunities', 0)}
• Total Lines of Code: {summary.get('total_lines', 0)}
• Refactoring Density: {summary.get('refactoring_density', 0):.2f} (per 1000 lines)

Opportunities by Pattern:
"""
        
        pattern_totals = summary.get('pattern_totals', {})
        for pattern, count in pattern_totals.items():
            if count > 0:
                pattern_name = pattern.replace('_', ' ').title()
                pattern_desc = self.analyzer.refactoring_patterns.get(pattern, {}).get('description', pattern_name)
                summary_text += f"• {pattern_name}: {count} opportunities\n"
                summary_text += f"  ({pattern_desc})\n"
        
        if files:
            summary_text += f"\nTop 5 Files by Refactoring Score:\n{'-' * 30}\n"
            for i, file_result in enumerate(files[:5], 1):
                summary_text += f"{i}. {file_result['file_name']} (Score: {file_result['refactoring_score']:.2f})\n"
        
        self.update_results_tab("Summary", summary_text)
        
        # Details tab
        details_text = "Detailed Refactoring Analysis\n" + "=" * 50 + "\n\n"
        
        for file_result in files[:10]:  # Show top 10 files
            details_text += f"File: {file_result['file_name']}\n"
            details_text += f"Path: {file_result['file_path']}\n"
            details_text += f"Refactoring Score: {file_result['refactoring_score']:.2f}\n"
            details_text += f"Opportunities: {file_result['opportunity_count']}\n"
            details_text += f"Lines: {file_result['total_lines']}\n\n"
            
            # Show opportunities for this file
            opportunities = file_result.get('opportunities', [])
            if opportunities:
                details_text += "Refactoring Opportunities:\n"
                for opp in opportunities[:5]:  # Show top 5 opportunities per file
                    details_text += f"  • Line {opp['line']}: {opp['description']} ({opp['severity']})\n"
                    details_text += f"    Pattern: {opp['pattern'].replace('_', ' ').title()}\n"
                    details_text += f"    Effort: {opp['effort_hours']} hours, Impact: {opp['impact_score']}\n"
                    if 'guidance' in opp and 'steps' in opp['guidance']:
                        details_text += f"    Steps: {len(opp['guidance']['steps'])} refactoring steps\n"
                    details_text += "\n"
            
            details_text += "-" * 50 + "\n\n"
        
        self.update_results_tab("Details", details_text)
        
        # Raw Data tab
        raw_data = json.dumps(self.current_results, indent=2, default=str)
        self.update_results_tab("Raw Data", raw_data)
        
        # Set results data for export
        self.set_results_data(self.current_results)
    
    def generate_recommendations(self):
        """Generate recommendations based on refactoring analysis"""
        if not self.current_results:
            return []
        
        recommendations = []
        summary = self.current_results.get('summary', {})
        
        total_score = summary.get('total_refactoring_score', 0)
        
        if total_score > 100:
            recommendations.append("High refactoring potential detected - consider dedicated refactoring iterations")
        
        pattern_totals = summary.get('pattern_totals', {})
        
        # Pattern-specific recommendations
        if pattern_totals.get('extract_method', 0) > 5:
            recommendations.append("Focus on method extraction to improve code modularity and readability")
        
        if pattern_totals.get('extract_class', 0) > 2:
            recommendations.append("Consider class extraction to improve separation of concerns")
        
        if pattern_totals.get('eliminate_duplication', 0) > 3:
            recommendations.append("Prioritize eliminating code duplication to reduce maintenance burden")
        
        if pattern_totals.get('simplify_conditionals', 0) > 5:
            recommendations.append("Simplify complex conditionals to improve code readability")
        
        return recommendations
    
    def _extract_key_metrics(self):
        """Extract key metrics for database storage"""
        if not self.current_results:
            return {}
        
        summary = self.current_results.get('summary', {})
        
        return {
            'total_refactoring_score': summary.get('total_refactoring_score', 0),
            'total_files': summary.get('total_files', 0),
            'total_opportunities': summary.get('total_opportunities', 0),
            'refactoring_density': summary.get('refactoring_density', 0),
            'average_score_per_file': summary.get('average_score_per_file', 0)
        }
    
    def generate_refactoring_visualization(self):
        """Generate visual refactoring analysis charts"""
        if not self.current_results:
            return
        
        # Clear existing visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        try:
            # Create matplotlib figure
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))
            fig.patch.set_facecolor('#1a1a1a')
            
            summary = self.current_results.get('summary', {})
            files = self.current_results.get('files', [])
            
            # 1. Opportunities by pattern (pie chart)
            pattern_totals = summary.get('pattern_totals', {})
            patterns = [pat.replace('_', ' ').title() for pat, count in pattern_totals.items() if count > 0]
            counts = [count for count in pattern_totals.values() if count > 0]
            
            if patterns:
                colors = plt.cm.Set3(np.linspace(0, 1, len(patterns)))
                ax1.pie(counts, labels=patterns, autopct='%1.1f%%', colors=colors, startangle=90)
                ax1.set_title('Opportunities by Pattern', color='white', fontsize=10, fontweight='bold')
            else:
                ax1.text(0.5, 0.5, 'No opportunities found', ha='center', va='center', 
                        transform=ax1.transAxes, color='white')
            
            # 2. Top files by refactoring score (bar chart)
            if files:
                top_files = files[:10]  # Top 10 files
                file_names = [f['file_name'][:20] + '...' if len(f['file_name']) > 20 else f['file_name'] 
                             for f in top_files]
                refactoring_scores = [f['refactoring_score'] for f in top_files]
                
                colors = ['red' if score > 50 else 'orange' if score > 20 else 'yellow' if score > 5 else 'green' 
                         for score in refactoring_scores]
                
                bars = ax2.barh(range(len(file_names)), refactoring_scores, color=colors, alpha=0.7)
                ax2.set_yticks(range(len(file_names)))
                ax2.set_yticklabels(file_names, color='white', fontsize=8)
                ax2.set_xlabel('Refactoring Score', color='white')
                ax2.set_title('Top Files by Refactoring Score', color='white', fontsize=10, fontweight='bold')
                ax2.tick_params(colors='white')
                ax2.set_facecolor('#2a2a2a')
                
                # Add value labels
                for i, (bar, score) in enumerate(zip(bars, refactoring_scores)):
                    ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                            f'{score:.1f}', va='center', color='white', fontsize=8)
            else:
                ax2.text(0.5, 0.5, 'No files analyzed', ha='center', va='center', 
                        transform=ax2.transAxes, color='white')
                ax2.set_facecolor('#2a2a2a')
            
            # 3. Effort vs Impact scatter plot
            if files:
                efforts = []
                impacts = []
                severities = []
                
                for file_result in files:
                    for opp in file_result.get('opportunities', []):
                        efforts.append(opp['effort_hours'])
                        impacts.append(opp['impact_score'])
                        severities.append(opp['severity'])
                
                if efforts and impacts:
                    # Color by severity
                    severity_colors = {'minor': 'green', 'moderate': 'yellow', 'major': 'orange', 'critical': 'red'}
                    colors = [severity_colors.get(sev, 'blue') for sev in severities]
                    
                    scatter = ax3.scatter(efforts, impacts, alpha=0.6, c=colors)
                    ax3.set_xlabel('Effort (Hours)', color='white')
                    ax3.set_ylabel('Impact Score', color='white')
                    ax3.set_title('Effort vs Impact Analysis', color='white', fontsize=10, fontweight='bold')
                    ax3.tick_params(colors='white')
                    ax3.set_facecolor('#2a2a2a')
                    
                    # Add quadrant lines
                    if efforts and impacts:
                        avg_effort = sum(efforts) / len(efforts)
                        avg_impact = sum(impacts) / len(impacts)
                        ax3.axvline(avg_effort, color='white', linestyle='--', alpha=0.5)
                        ax3.axhline(avg_impact, color='white', linestyle='--', alpha=0.5)
                else:
                    ax3.text(0.5, 0.5, 'No opportunity data', ha='center', va='center', 
                            transform=ax3.transAxes, color='white')
                    ax3.set_facecolor('#2a2a2a')
            else:
                ax3.text(0.5, 0.5, 'No data for analysis', ha='center', va='center', 
                        transform=ax3.transAxes, color='white')
                ax3.set_facecolor('#2a2a2a')
            
            # 4. Severity distribution (bar chart)
            if files:
                severity_counts = {'minor': 0, 'moderate': 0, 'major': 0, 'critical': 0}
                
                for file_result in files:
                    for opp in file_result.get('opportunities', []):
                        severity = opp.get('severity', 'minor')
                        severity_counts[severity] += 1
                
                severities = list(severity_counts.keys())
                counts = list(severity_counts.values())
                colors = ['green', 'yellow', 'orange', 'red']
                
                bars = ax4.bar(severities, counts, color=colors, alpha=0.7)
                ax4.set_xlabel('Severity', color='white')
                ax4.set_ylabel('Number of Opportunities', color='white')
                ax4.set_title('Opportunities by Severity', color='white', fontsize=10, fontweight='bold')
                ax4.tick_params(colors='white')
                ax4.set_facecolor('#2a2a2a')
                
                # Add value labels
                for bar, count in zip(bars, counts):
                    if count > 0:
                        ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                                str(count), ha='center', va='bottom', color='white', fontsize=8)
            else:
                ax4.text(0.5, 0.5, 'No severity data', ha='center', va='center', 
                        transform=ax4.transAxes, color='white')
                ax4.set_facecolor('#2a2a2a')
            
            # Style all axes
            for ax in [ax1, ax2, ax3, ax4]:
                for spine in ax.spines.values():
                    spine.set_color('white')
            
            plt.tight_layout()
            
            # Embed in tkinter
            canvas = FigureCanvasTkAgg(fig, self.viz_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
            
        except Exception as e:
            error_label = tk.Label(self.viz_frame, text=f"Error generating visualization: {str(e)}",
                                 bg=BG_COLOR, fg="red", font=("Consolas", 10))
            error_label.pack(expand=True)
    
    def clear_results(self):
        """Clear all analysis results and visualizations"""
        self.current_results = None
        
        # Clear results tabs
        for tab_name in ["Summary", "Details", "Analysis", "Raw Data"]:
            self.update_results_tab(tab_name, "")
        
        # Clear refactoring plan tab if it exists
        if hasattr(self, 'tab_frames') and "Refactoring Plan" in self.tab_frames:
            self.update_results_tab("Refactoring Plan", "")
        
        # Clear visualization
        for widget in self.viz_frame.winfo_children():
            widget.destroy()
        
        placeholder_label = tk.Label(self.viz_frame, text="Analyze code to see refactoring opportunities visualization",
                                   bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10))
        placeholder_label.pack(expand=True)
        
        # Reset progress
        self.update_progress(0, "Ready")
        
        messagebox.showinfo("Cleared", "All results have been cleared.")