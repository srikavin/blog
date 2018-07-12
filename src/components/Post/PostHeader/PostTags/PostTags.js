import React from 'react';
import {Popover, PopoverInteractionKind, Position, Tag} from '@blueprintjs/core';
import './PostTags.css'

class PostTags extends React.Component {
    genTagsBlock() {
        if (!this.props.tags) {
            return <div className={'post-tag-description-container bp3-skeleton'}/>
        }
        return this.props.tags && this.props.tags.map(e => (
            <Popover hoverCloseDelay={0} hoverOpenDelay={150} position={Position.BOTTOM}
                     interactionKind={PopoverInteractionKind.HOVER_TARGET_ONLY} key={e.name}>
                <Tag interactive={true} className={'post-tag-item'} minimal={true}>{e.name}</Tag>
                <div className={'post-tag-description-container'}>{e.description}</div>
            </Popover>
        ));
    }

    render() {
        return (
            <div className={this.props.className}>
                {this.genTagsBlock()}
            </div>
        );
    }
}

export default PostTags;