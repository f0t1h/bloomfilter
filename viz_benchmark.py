#!/usr/bin/env python3
"""
Bloom Filter Benchmark Visualization Script
Generates plots from any benchmark TSV file
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
import argparse

def load_data(filename):
    """Load benchmark results from TSV file"""
    if not os.path.exists(filename):
        print(f"Error: {filename} not found. Run the benchmark first.")
        return None
    
    df = pd.read_csv(filename, sep='\t')
    print(f"Loaded {len(df)} benchmark results from {filename}")
    return df

def plot_throughput_vs_threads(df, metric, title, filename):
    """Plot throughput vs threads for different filter types with confidence intervals"""
    plt.figure(figsize=(12, 8))
    
    # Use seaborn lineplot with confidence intervals
    sns.lineplot(data=df, x='threads', y=metric, hue='filter', 
                 marker='o', linewidth=2, markersize=8, errorbar=('ci', 95))
    
    plt.xlabel('Number of Threads')
    plt.ylabel(metric.replace('_', ' ').title())
    plt.title(title)
    plt.legend(loc='best')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {filename}")

def plot_error_rates(df, metric, title, filename):
    """Plot error rates vs threads with confidence intervals"""
    plt.figure(figsize=(12, 8))
    
    # Use seaborn lineplot with confidence intervals
    sns.lineplot(data=df, x='threads', y=metric, hue='filter', 
                 marker='o', linewidth=2, markersize=8, errorbar=('ci', 95))
    
    plt.xlabel('Number of Threads')
    plt.ylabel(metric.replace('_', ' ').title())
    plt.title(title)
    plt.yscale('log')
    plt.legend(loc='best')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {filename}")

def plot_bits_vs_threads(df, title, filename):
    """Plot total bits vs threads with confidence intervals"""
    plt.figure(figsize=(12, 8))
    
    # Use seaborn lineplot with confidence intervals
    sns.lineplot(data=df, x='threads', y='total_bits', hue='filter', 
                 marker='o', linewidth=2, markersize=8, errorbar=('ci', 95))
    
    plt.xlabel('Number of Threads')
    plt.ylabel('Total Bits')
    plt.title(title)
    plt.legend(loc='best')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {filename}")

def detect_benchmark_type(df):
    """Detect the type of benchmark based on available columns"""
    columns = df.columns.tolist()
    
    if 'InsertOpsPerSec' in columns and 'QueryOpsPerSec' in columns:
        return 'external_filters'
    elif 'insert_throughput' in columns and 'contains_throughput' in columns:
        return 'gloom'
    elif 'insert_ms' in columns and 'contains_ms' in columns:
        return 'simple_benchmark'
    else:
        return 'unknown'

def prepare_data(df, benchmark_type):
    """Prepare data based on benchmark type"""
    if benchmark_type == 'external_filters':
        # Rename columns to standard format
        df = df.rename(columns={
            'Filter': 'filter',
            'Threads': 'threads',
            'InsertTimeMs': 'insert_ms',
            'QueryTimeMs': 'query_ms',
            'InsertOpsPerSec': 'insert_ops_per_sec',
            'QueryOpsPerSec': 'query_ops_per_sec',
            'FalsePositiveRate': 'fp_rate',
            'FalseNegativeRate': 'fn_rate'
        })
        
        # Convert to millions for better readability
        df['insert_throughput'] = df['insert_ops_per_sec'] / 1000000.0
        df['query_throughput'] = df['query_ops_per_sec'] / 1000000.0
        
    elif benchmark_type == 'gloom':
        # Data is already in the right format
        pass
    
    # Calculate throughput from time measurements for all benchmark types
    if 'insert_ms' in df.columns and 'insert_count' in df.columns:
        # Calculate insert throughput: (insert_count / insert_ms) * 1000 to get ops/sec, then convert to M ops/sec
        df['insert_throughput'] = (df['insert_count'] / df['insert_ms']) * 1000.0 / 1000000.0
    
    if 'contains_ms' in df.columns and 'test_count' in df.columns:
        # Calculate contains/query throughput: (test_count / contains_ms) * 1000 to get ops/sec, then convert to M ops/sec
        df['contains_throughput'] = (df['test_count'] / df['contains_ms']) * 1000.0 / 1000000.0
    elif 'query_ms' in df.columns and 'test_count' in df.columns:
        # Alternative naming for query operations
        df['contains_throughput'] = (df['test_count'] / df['query_ms']) * 1000.0 / 1000000.0
    
    return df

def plot_throughput_vs_threads_generic(df, metric, title, filename, ylabel=None):
    """Generic plot throughput vs threads for different filter types"""
    plt.figure(figsize=(12, 8))
    
    # Use seaborn lineplot with confidence intervals
    sns.lineplot(data=df, x='threads', y=metric, hue='filter', 
                 marker='o', linewidth=2, markersize=8, errorbar=('ci', 95))
    
    plt.xlabel('Number of Threads')
    plt.ylabel(ylabel or metric.replace('_', ' ').title())
    plt.title(title)
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {filename}")

def main():
    """Generate all benchmark visualizations"""
    parser = argparse.ArgumentParser(description='Generate visualizations from benchmark TSV files')
    parser.add_argument('tsv_file', nargs='?', default='benchmark_results.tsv',
                       help='TSV file to visualize (default: benchmark_results.tsv)')
    parser.add_argument('--output-dir', '-o', default='benchmark_plots',
                       help='Output directory for plots (default: benchmark_plots)')
    parser.add_argument('--prefix', '-p', default='',
                       help='Prefix for output filenames')
    
    args = parser.parse_args()
    
    print("Bloom Filter Benchmark Visualization")
    print("=" * 40)
    print(f"Input file: {args.tsv_file}")
    print(f"Output directory: {args.output_dir}")
    
    # Load data
    df = load_data(args.tsv_file)
    if df is None:
        return
    
    # Detect benchmark type
    benchmark_type = detect_benchmark_type(df)
    print(f"Detected benchmark type: {benchmark_type}")
    
    # Prepare data
    df = prepare_data(df, benchmark_type)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Set seaborn style for better looking plots
    sns.set_style("whitegrid")
    sns.set_palette("husl")
    
    print("\nGenerating plots...")
    
    # Determine available metrics and create plots
    prefix = f"{args.prefix}_" if args.prefix else ""
    
    if 'insert_throughput' in df.columns:
        plot_throughput_vs_threads_generic(df, 'insert_throughput', 
                                          'Insert Throughput vs Threads (95% CI)', 
                                          f'{args.output_dir}/{prefix}insert_throughput_vs_threads.png',
                                          'Insert Throughput (M ops/sec)')
    
    if 'query_throughput' in df.columns:
        plot_throughput_vs_threads_generic(df, 'query_throughput', 
                                          'Query Throughput vs Threads (95% CI)', 
                                          f'{args.output_dir}/{prefix}query_throughput_vs_threads.png',
                                          'Query Throughput (M ops/sec)')
    elif 'contains_throughput' in df.columns:
        plot_throughput_vs_threads_generic(df, 'contains_throughput', 
                                          'Contains Throughput vs Threads (95% CI)', 
                                          f'{args.output_dir}/{prefix}contains_throughput_vs_threads.png',
                                          'Contains Throughput (M ops/sec)')
    
    if 'fp_rate' in df.columns:
        plot_error_rates(df, 'fp_rate', 
                        'False Positive Rate vs Threads (95% CI)', 
                        f'{args.output_dir}/{prefix}fp_rate_vs_threads.png')
    
    if 'fn_rate' in df.columns:
        plot_error_rates(df, 'fn_rate', 
                        'False Negative Rate vs Threads (95% CI)', 
                        f'{args.output_dir}/{prefix}fn_rate_vs_threads.png')
    
    if 'total_bits' in df.columns:
        plot_bits_vs_threads(df, 
                            'Total Bits vs Threads (95% CI)', 
                            f'{args.output_dir}/{prefix}total_bits_vs_threads.png')
    
    print(f"\nAll plots saved to '{args.output_dir}/' directory")
    
    # Show summary statistics
    print("\nSummary statistics:")
    numeric_cols = df.select_dtypes(include=['number']).columns
    summary_cols = [col for col in numeric_cols if col not in ['threads']]
    if summary_cols:
        print(df.groupby('filter')[summary_cols].agg(['mean', 'std']))

if __name__ == '__main__':
    main()
