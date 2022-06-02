import { Options, PolicyOptions } from '../types';
import { BadResult, GoodResult } from '../../cli/commands/monitor/types';
import { Ecosystem, ScanResult, EcosystemMonitorResult, EcosystemMonitorError, MonitorDependenciesRequest } from './types';
export declare function monitorEcosystem(ecosystem: Ecosystem, paths: string[], options: Options & PolicyOptions): Promise<[EcosystemMonitorResult[], EcosystemMonitorError[]]>;
export declare function generateMonitorDependenciesRequest(scanResult: ScanResult, options: Options): Promise<MonitorDependenciesRequest>;
export declare function getFormattedMonitorOutput(results: Array<GoodResult | BadResult>, monitorResults: EcosystemMonitorResult[], errors: EcosystemMonitorError[], options: Options): Promise<string>;
