import React, {Component} from 'react';
import PropTypes from 'prop-types';
import Select from 'react-select';

class ItemSelector extends Component {
    render() {
        return (
            <div className={this.props.className ? this.props.className : ''}>
                <Select isMulti={true}
                        isLoading={this.props.loading}
                        options={this.props.tags}
                        onChange={this.props.onChange}
                        getOptionLabel={(e) => e.name}
                        value={this.props.value}
                        placeholder={this.props.placeholder}
                        getOptionValue={(e) => e.id}/>
            </div>
        )
    }
}

ItemSelector.propTypes = {
    tags: PropTypes.arrayOf(PropTypes.any).isRequired,
    loading: PropTypes.bool.isRequired,
    onChange: PropTypes.func.isRequired,
    placeholder: PropTypes.string,
    className: PropTypes.string,
    value: PropTypes.arrayOf(PropTypes.any).isRequired
};

export default ItemSelector;