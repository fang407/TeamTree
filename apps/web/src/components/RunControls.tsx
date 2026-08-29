export function RunControls({
  active,
  disabled,
  onStop,
}: {
  active: boolean;
  disabled: boolean;
  onStop: () => void;
}) {
  return (
    <button
      className="button button-danger run-stop-button"
      type="button"
      disabled={!active || disabled}
      onClick={onStop}
    >
      Stop Run
    </button>
  );
}
