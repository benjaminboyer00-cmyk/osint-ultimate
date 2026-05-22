"""Recherche multi-plateformes type Sherlock."""
import json
import shutil
import subprocess


def search(username: str, fallback_fn=None, timeout: int = 90) -> dict:
    """
    Lance Sherlock CLI si disponible, sinon utilise fallback_fn (scan_pseudo).
    """
    username = username.strip().lstrip('@')
    if not username:
        return {'Erreur': 'Pseudo vide'}

    sherlock_bin = shutil.which('sherlock') or shutil.which('sherlock-project')
    if sherlock_bin:
        try:
            proc = subprocess.run(
                [sherlock_bin, username, '--print-found', '--timeout', '10', '--no-color'],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            results = {}
            for line in (proc.stdout or '').splitlines():
                line = line.strip()
                if not line or line.startswith('[*]') or line.startswith('[-]'):
                    continue
                if 'http' in line.lower():
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        site = parts[0].strip()
                        url = parts[1].strip()
                        results[site] = f'✓ Existe — {url}'
            if results:
                results['_source'] = 'sherlock-cli'
                results['_found_count'] = len(results) - 1 if '_source' in results else len(results)
                return results
        except subprocess.TimeoutExpired:
            return {'Erreur': 'Sherlock timeout — réessayez ou utilisez le mode Expert'}
        except Exception as e:
            pass

    try:
        import sherlock_project.sherlock as sherlock_mod
        from sherlock_project.sherlock import sherlock as sherlock_run
        # API interne variable selon version — repli subprocess prioritaire
    except ImportError:
        pass

    if fallback_fn:
        out = fallback_fn(username)
        out['_source'] = out.get('_source', 'builtin-pseudo-scan')
        return out

    return {'Erreur': 'Sherlock non installé et aucun repli disponible'}
