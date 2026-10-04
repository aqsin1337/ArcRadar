import type {
  DomainProfile,
  HashProfile,
  HashType,
  IntelProvider,
  IpProfile,
  LookupContext,
  ProviderInfo,
  UrlProfile,
} from "../types";
import { demoDomainProfile, demoHashProfile, demoIpProfile, demoUrlProfile } from "./demo-data";

/**
 * The built-in provider: it answers from a small sample dataset in code, needs no key and no
 * network, and is what makes ArcRadar work straight after installation. Its `origin` is `demo`, so
 * everything it returns is labelled as sample data. It has records only for the fictional
 * scenario (and a few harmless well-known subjects); for anything else it honestly has no record.
 */
export class DemoProvider implements IntelProvider {
  readonly info: ProviderInfo = { id: "demo", name: "Demo dataset", origin: "demo" };

  async lookupIp(ip: string, context: LookupContext): Promise<IpProfile | null> {
    return demoIpProfile(ip, context.now);
  }

  async lookupDomain(domain: string, context: LookupContext): Promise<DomainProfile | null> {
    return demoDomainProfile(domain, context.now);
  }

  async lookupUrl(url: string, context: LookupContext): Promise<UrlProfile | null> {
    return demoUrlProfile(url, context.now);
  }

  async lookupHash(
    hash: string,
    type: HashType,
    context: LookupContext,
  ): Promise<HashProfile | null> {
    return demoHashProfile(hash, type, context.now);
  }
}
